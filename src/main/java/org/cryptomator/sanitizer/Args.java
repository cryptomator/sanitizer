package org.cryptomator.sanitizer;

import static java.lang.String.format;
import static java.lang.String.join;
import static java.nio.charset.Charset.defaultCharset;
import static java.nio.file.Files.exists;
import static java.nio.file.Files.isDirectory;
import static java.nio.file.Files.isReadable;
import static java.nio.file.Files.isRegularFile;
import static java.util.Arrays.asList;
import static java.util.Arrays.fill;

import java.io.Console;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
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

	private static final String USAGE = "java -jar sanitizer-" + Version.get() + ".jar -vault vaultToCheck [-passphraseFile passphraseFile] [-solve enabledSolution ...] [-output outputFile]";
	private static final String HEADER = "\nDetects problems in Cryptomator vaults.\n\n";
	private static final Options OPTIONS = new Options();
	private static final Set<String> ALLOWED_PROBLEMS_TO_SOLVE = new HashSet<>(asList("LowercasedFile", "MissingEqualsSign", "OrphanMFile", "UppercasedFile"));
	static {
		OPTIONS.addOption(Option.builder() //
				.longOpt("vault") //
				.hasArg() //
				.argName("vaultPath") //
				.desc("The vault to check.") //
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
				.argName("outputFile") //
				.desc("The file to write results to. Default: <vaultname>.vaultcheck.txt") //
				.build());
	}

	private final Path vaultLocation;
	private final Path outputFile;
	private CharBuffer passphrase;
	private final Set<String> problemsToSolve;

	public Args(CommandLine commandLine) throws ParseException {
		this.vaultLocation = vaultLocation(commandLine);
		this.passphrase = passphrase(commandLine);
		this.outputFile = outputFile(commandLine);
		this.problemsToSolve = problemsToSolve(commandLine);
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

	private CharBuffer passphrase(CommandLine commandLine) throws ParseException {
		String value = commandLine.getOptionValue("passphrase");
		String file = commandLine.getOptionValue("passphraseFile");
		if (value != null && file != null) {
			throw new ParseException("Only passphrase or passphraseFile can be present, not both.");
		}
		if (value != null) {
			return CharBuffer.wrap(value.toCharArray());
		}
		if (file != null) {
			return passphraseFromFile(file);
		}
		return null;
	}

	private CharBuffer passphraseFromFile(String file) throws ParseException {
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
			byte[] bytes = Files.readAllBytes(path);
			CharBuffer result = CharBuffer.allocate(bytes.length);
			defaultCharset().newDecoder().decode(ByteBuffer.wrap(bytes), result, true);
			fill(bytes, (byte) 0);
			result.flip();
			return result;
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

	public Optional<CharBuffer> passphraseIfRead() {
		return Optional.ofNullable(passphrase);
	}

	public CharBuffer passphrase() throws AbortCheckException {
		if (passphrase == null) {
			passphrase = readPassphrase();
		}
		return passphrase;
	}

	private CharBuffer readPassphrase() throws AbortCheckException {
		Console console = System.console();
		if (console == null) {
			throw new AbortCheckException("Could not get system console to read passphrase. You may use a passphrase file instead.");
		}
		return CharBuffer.wrap(console.readPassword("Vault password: "));
	}

	public Path outputFile() {
		return outputFile;
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

	private Path outputFile(CommandLine commandLine) throws ParseException {
		String output = commandLine.getOptionValue("output");
		if (output == null) {
			output = vaultLocation.getFileName().toString() + ".vaultcheck.txt";
			int i = 2;
			while (exists(Paths.get(output))) {
				output = vaultLocation.getFileName().toString() + "_" + (i++) + ".vaultcheck.txt";
			}
		}
		try {
			Path path = Paths.get(output);
			if (exists(path)) {
				throw new ParseException("Output file exists");
			}
			return path;
		} catch (InvalidPathException e) {
			throw new ParseException("Invalid output file");
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
