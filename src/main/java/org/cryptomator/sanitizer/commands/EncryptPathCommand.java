package org.cryptomator.sanitizer.commands;

import static java.nio.file.Files.isDirectory;
import static java.nio.file.Files.isReadable;
import static java.nio.file.Files.isRegularFile;

import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.cryptomator.sanitizer.Passphrase;
import org.cryptomator.sanitizer.integrity.AbortCheckException;

public class EncryptPathCommand implements Command {

	private static final String USAGE = "" //
			+ "-vault vaultPath" //
			+ " [-passphraseFile passphraseFile]"
			+ " [-cleartextPath cleartextPath]"
			+ " [-cleartextListFile cleartextListFile]"
			+ " [-outputPath outputPath]";
	private static final String HEADER = "\nEncrypt cleartext paths for a Cryptomator vault.\n";
	private static final Options OPTIONS = new Options();

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
				.longOpt("cleartextPath") //
				.hasArg() //
				.argName("cleartextPath") //
				.desc("Path of the cleartext file in the vault. Omit this and you will be prompted for the path.") //
				.build());
		OPTIONS.addOption(Option.builder()
				.longOpt("cleartextListFile")
				.hasArg()
				.argName("cleartextListFile")
				.desc("Path to a line-separated file that lists cleartexts in the vault. This can be used to substitute for cleartextPath.")
				.build());
		OPTIONS.addOption(Option.builder()
				.longOpt("outputPath")
				.hasArg()
				.argName("outputPath")
				.desc("Path of the output file. Supported extensions: txt, csv")
				.build());
	}

	private Path vaultLocation;
	private Passphrase passphrase;
	private List<String> cleartextList;
	private String outputPath;

	@Override
	public String commandLineValue() {
		return "encryptPath";
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
		new EncryptPathRunner(this).run();
	}

	@Override
	public void parse(String[] arguments) throws ParseException {
		CommandLine commandLine = new DefaultParser().parse(OPTIONS, arguments);
		this.vaultLocation = vaultLocation(commandLine);
		this.passphrase = passphrase(commandLine);
		this.cleartextList = this.cleartextList(commandLine);
		this.outputPath = outputPath(commandLine);
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

	public List<String> cleartextList() {
		return cleartextList;
	}

	public String outputPath() {
		return outputPath;
	}

	private Passphrase readPassphrase() throws AbortCheckException {
		Console console = System.console();
		if (console == null) {
			throw new AbortCheckException("Could not get system console to read passphrase. You may use a passphrase file instead.");
		}
		return new Passphrase(console.readPassword("Vault password: "));
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

	private List<String> cleartextList(CommandLine commandLine) throws ParseException {
		if (commandLine.hasOption("cleartextPath")) {
			return Arrays.asList(new String[]{commandLine.getOptionValue("cleartextPath")});
		} else {
			if (commandLine.hasOption("cleartextListFile")) {
				try {
					return Files.readAllLines(Paths.get(commandLine.getOptionValue("cleartextListFile")));
				} catch (IOException e) {
					throw new ParseException(e.toString());
				}
			} else {
				return null;
			}
		}
	}

	private String outputPath(CommandLine commandLine) {
		if (commandLine.hasOption("outputPath")) {
			String outputPathRaw = commandLine.getOptionValue("outputPath");
			return outputPathRaw;
		} else {
			return null;
		}
	}

}
