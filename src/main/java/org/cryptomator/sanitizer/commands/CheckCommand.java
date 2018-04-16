package org.cryptomator.sanitizer.commands;

import org.apache.commons.cli.*;
import org.cryptomator.sanitizer.Passphrase;
import org.cryptomator.sanitizer.integrity.AbortCheckException;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import static java.lang.String.format;
import static java.lang.String.join;
import static java.nio.file.Files.*;
import static java.util.Arrays.asList;

class CheckCommand implements Command {

	private static final String USAGE = "" //
			+ "-vault vaultPath" //
			+ " [-passphraseFile passphraseFile]" //
			+ " [-deep]" //
			+ " [-solve enabledSolution ...]" //
			+ " [-output outputPrefix]";
	private static final String HEADER = "\nDetects problems in Cryptomator vaults.\n";
	public static final Options OPTIONS = new Options();
	private static final Set<String> ALLOWED_PROBLEMS_TO_SOLVE = new HashSet<>(asList( //
			"LowercasedFile", //
			"MissingEqualsSign", //
			"OrphanMFile", //
			"UppercasedFile", //
			"FileSizeOfZeroInHeader", //
			"FileSizeInHeader", //
			"NameNormalization"));

	static {
		OPTIONS.addOption(Option.builder() //
				.longOpt("vault") //
				.hasArg() //
				.argName("vaultPath") //
				.desc("On which vault to work.") //
				.required() //
				.build());
		OPTIONS.addOption(Option.builder() //
				.longOpt("passphrase") //
				.hasArg() //
				.argName("passphrase") //
				.desc("DO NOT USE. ONLY FOR TESTING PURPOSES. The cleartext vault passphrase. Omit this and you will be promted for the passphrase.") //
				.build());
		OPTIONS.addOption(Option.builder() //
				.longOpt("passphraseFile") //
				.hasArg() //
				.argName("passphraseFile") //
				.desc("A file to read the password from. Omit this and you will be promted for the passphrase.") //
				.build());
		OPTIONS.addOption(Option.builder() //
				.longOpt("solve") //
				.hasArgs() //
				.argName("solve") //
				.desc("Name of one or more problems to solve. Available: " + join(", ", ALLOWED_PROBLEMS_TO_SOLVE)) //
				.build());
		OPTIONS.addOption(Option.builder() //
				.longOpt("deep") //
				.desc("Check file integrity (Could take a long time).") //
				.build());
		OPTIONS.addOption(Option.builder() //
				.longOpt("output") //
				.hasArg() //
				.argName("outputPrefix") //
				.desc("The prefix of the output files to write results to. Will create two output files:\n" //
						+ "* <outputPrefix>.structure.txt and\n" //
						+ "* <outputPrefix>.check.txt.\n" //
						+ "Default: name of vault") //
				.build());
	}

	private Path vaultLocation;
	private Passphrase passphrase;
	private Set<String> problemsToSolve;
	private boolean deep;

	private Path checkOutputFile;
	private Path structureOutputFile;

	@Override
	public String commandLineValue() {
		return "check";
	}

	@Override
	public void printUsage() {
		System.out.println(USAGE);
		System.out.println(HEADER);
		PrintWriter writer = new PrintWriter(System.out);
		new HelpFormatter().printOptions(writer, 80, OPTIONS, 1, 3);
		writer.flush();
	}

	@Override
	public void run() {
		new CheckRunner(this).run();
	}

	@Override
	public void parse(String[] arguments) throws ParseException {
		CommandLine commandLine = new DefaultParser().parse(OPTIONS, arguments);
		this.vaultLocation = vaultLocation(commandLine);
		this.passphrase = passphrase(commandLine);
		this.problemsToSolve = problemsToSolve(commandLine);
		this.deep = commandLine.hasOption("deep");
		setOutputFiles(commandLine);
	}

	private Set<String> problemsToSolve(CommandLine commandLine) throws ParseException {
		String[] values = commandLine.getOptionValues("solve");
		if (values == null) {
			return Collections.emptySet();
		} else {
			Set<String> result = new HashSet<>(asList(values));
			Set<String> disallowed = new HashSet<>(result);
			disallowed.removeAll(ALLOWED_PROBLEMS_TO_SOLVE);
			if (!disallowed.isEmpty()) {
				throw new ParseException(format("Problems %s unknown or cannot be solved", join(", ", disallowed)));
			}
			return result;
		}
	}

	private Passphrase passphrase(CommandLine commandLine) throws ParseException {
		String value = commandLine.getOptionValue("passphrase");
		String file = commandLine.getOptionValue("passphraseFile");
		if (value != null && file != null) {
			throw new ParseException("Only passphrase or passphraseFile can be present, not both.");
		}
		if (value != null) {
			return new Passphrase(value.toCharArray());
		}
		if (file != null) {
			return passphraseFromFile(file);
		}
		return null;
	}

	private Passphrase passphraseFromFile(String file) throws ParseException {
		Path path;
		try {
			path = Paths.get(file);
		} catch (InvalidPathException e) {
			throw new ParseException("Invalid passphrase file");
		}
		if (!isRegularFile(path)) {
			throw new ParseException("Invalid passphrase file");
		}
		if (!isReadable(path)) {
			throw new ParseException("Passphrase file not readable");
		}
		try {
			long pwFileSize = Files.size(path);
			if (pwFileSize > Integer.MAX_VALUE) {
				throw new ParseException("Invalid passphrase file");
			}
			assert pwFileSize <= Integer.MAX_VALUE;
			byte[] bytes = Files.readAllBytes(path);
			try {
				CharBuffer chars = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(bytes));
				try {
					return new Passphrase(chars);
				} finally {
					chars.clear();
					while (chars.hasRemaining()) {
						chars.put('\0');
					}
				}
			} finally {
				Arrays.fill(bytes, (byte) 0);
			}
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	public Set<String> problemsToSolve() {
		return problemsToSolve;
	}

	public Path vaultLocation() {
		return vaultLocation;
	}

	public Optional<Passphrase> passphraseIfRead() {
		return Optional.ofNullable(passphrase);
	}

	public Passphrase passphrase() throws AbortCheckException {
		if (passphrase == null) {
			passphrase = readPassphrase();
		}
		return passphrase;
	}

	private Passphrase readPassphrase() throws AbortCheckException {
		Console console = System.console();
		if (console == null) {
			throw new AbortCheckException("Could not get system console to read passphrase. You may use a passphrase file instead.");
		}
		return new Passphrase(console.readPassword("Vault password: "));
	}

	public Path structureOutputFile() {
		return structureOutputFile;
	}

	public boolean isDeep() {
		return deep;
	}

	public Path checkOutputFile() {
		return checkOutputFile;
	}

	private Path vaultLocation(CommandLine commandLine) throws ParseException {
		String vault = commandLine.getOptionValue("vault");
		try {
			Path path = Paths.get(vault);
			if (isDirectory(path)) {
				return path;
			}
		} catch (InvalidPathException e) {
			// handled below
		}
		throw new ParseException("vaultLocation is not a directory");
	}

	private void setOutputFiles(CommandLine commandLine) throws ParseException {
		String prefix = commandLine.getOptionValue("output");
		if (prefix == null) {
			prefix = vaultLocation.getFileName().toString();
		}
		String structureOutput = prefix + ".structure.txt";
		String checkOutput = prefix + ".check.txt";
		if (exists(Paths.get(structureOutput)) || exists(Paths.get(checkOutput))) {
			String input;
			do {
				System.out.print("Output file(s) exist. Overwrite [Y|n]? ");
				try {
					input = new BufferedReader(new InputStreamReader(System.in)).readLine();
				} catch (IOException e) {
					throw new UncheckedIOException(e);
				}
			} while (input != null && !input.matches("[yYnN]?"));
			if (input == null || input.equalsIgnoreCase("n")) {
				throw new ParseException("Output file(s) exists");
			}
		}
		try {
			structureOutputFile = Paths.get(structureOutput);
			checkOutputFile = Paths.get(checkOutput);
			deleteIfExists(structureOutputFile);
			deleteIfExists(checkOutputFile);
		} catch (InvalidPathException e) {
			throw new ParseException("Invalid output file");
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

}
