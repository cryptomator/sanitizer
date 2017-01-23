package org.cryptomator.sanitizer;

import static java.lang.String.format;
import static java.lang.String.join;
import static java.nio.file.Files.deleteIfExists;
import static java.nio.file.Files.exists;
import static java.nio.file.Files.isDirectory;
import static java.nio.file.Files.isReadable;
import static java.nio.file.Files.isRegularFile;
import static java.util.Arrays.asList;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.cryptomator.sanitizer.integrity.AbortCheckException;

public class Args {

	private static final String[] COMMANDS = new String[] {"check", "deepCheck", "solve", "encryptPath"};
	private static final String USAGE = "java -jar sanitizer-" + Version.get() + ".jar" //
			+ " -vault vaultToCheck" //
			+ " -cmd " + org.apache.commons.lang3.StringUtils.join(COMMANDS, '|') //
			+ " [-passphraseFile passphraseFile]" //
			+ " [-solve enabledSolution ...]" //
			+ " [-output outputPrefix]";
	private static final String HEADER = "\nDetects problems in Cryptomator vaults.\n\n";
	private static final Options OPTIONS = new Options();
	private static final Set<String> ALLOWED_PROBLEMS_TO_SOLVE = new HashSet<>(asList("LowercasedFile", "MissingEqualsSign", "OrphanMFile", "UppercasedFile"));
	static {
		OPTIONS.addOption(Option.builder() //
				.longOpt("vault") //
				.hasArg() //
				.argName("vaultPath") //
				.desc("On which vault to work.") //
				.required() //
				.build());
		OPTIONS.addOption(Option.builder() //
				.longOpt("cmd") //
				.hasArg() //
				.argName("command") //
				.desc("What to do (" + org.apache.commons.lang3.StringUtils.join(COMMANDS, ',') + ")") //
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
				.longOpt("output") //
				.hasArg() //
				.argName("outputPrefix") //
				.desc("The prefix of the output files to write results to. Will create two output files:\n" //
						+ "* <outputPrefix>.structure.txt and\n" //
						+ "* <outputPrefix>.check.txt.\n" //
						+ "Default: name of vault") //
				.build());
	}

	private final Path vaultLocation;
	private final String command;
	private Passphrase passphrase;
	private final Set<String> problemsToSolve;

	private Path checkOutputFile;
	private Path structureOutputFile;

	public Args(CommandLine commandLine) throws ParseException {
		this.vaultLocation = vaultLocation(commandLine);
		this.command = commandLine.getOptionValue("cmd");
		this.passphrase = passphrase(commandLine);
		this.problemsToSolve = problemsToSolve(commandLine);
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
			char[] chars = new char[(int) pwFileSize];
			try (InputStream in = Files.newInputStream(path, StandardOpenOption.READ); //
					Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
				int off = 0, read;
				while ((read = reader.read(chars, off, 1024)) != -1) {
					off += read;
				}
			}
			return new Passphrase(chars);
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

	public String command() {
		return command;
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

	public static Optional<Args> parse(String[] arguments) {
		try {
			CommandLine commandLine = new DefaultParser().parse(OPTIONS, arguments);
			return Optional.of(new Args(commandLine));
		} catch (ParseException e) {
			System.err.println(e.getMessage());
			printUsage();
			return Optional.empty();
		}
	}

	public static void printUsage() {
		new HelpFormatter().printHelp(USAGE, HEADER, OPTIONS, "");
	}

}
