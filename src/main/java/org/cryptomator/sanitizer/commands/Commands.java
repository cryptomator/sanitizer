package org.cryptomator.sanitizer.commands;

import static java.util.Arrays.copyOfRange;
import static java.util.Arrays.stream;
import static org.cryptomator.sanitizer.Sanitizer.print;
import static org.cryptomator.sanitizer.Sanitizer.printNoNewline;

import java.util.Optional;

import org.apache.commons.cli.ParseException;
import org.cryptomator.sanitizer.Version;

public class Commands {

	private static final String GENERIC_USAGE = "java -jar sanitizer-" + Version.get() + ".jar ";

	private static final Command[] COMMANDS = { //
			new CheckCommand(), //
			new DecryptFileCommand(), //
			new EncryptPathCommand(), //
			new DecryptVaultCommand() //
	};

	public static Optional<Commands> parse(String[] arguments) {
		try {
			return Optional.of(new Commands(arguments));
		} catch (ParseException e) {
			print("ERROR: " + e.getMessage(), System.err);
			print(System.err);
			printGenericUsage();
			printCommandsUsage();
			return Optional.empty();
		}
	}

	private static void printGenericUsage() {
		print("# usage");
		print(GENERIC_USAGE + "command ...");
		print();
		print("commands:");
		stream(COMMANDS).forEach(command -> print("* " + command.commandLineValue()));
		print();
	}

	private static void printCommandsUsage() {
		stream(COMMANDS).forEach(Commands::printUsage);
	}

	private static void printUsage(Command command) {
		print("# " + command.commandLineValue() + " command usage");
		printNoNewline(GENERIC_USAGE + command.commandLineValue() + " ");
		command.printUsage();
		print();
	}

	private final Command command;

	private Commands(String[] arguments) throws ParseException {
		command = extractCommand(arguments);
		String[] argumentsWithoutFirstElement = copyOfRange(arguments, 1, arguments.length);
		command.parse(argumentsWithoutFirstElement);
	}

	private Command extractCommand(String[] arguments) throws ParseException {
		if (arguments.length < 1) {
			throw new ParseException("No command provided");
		}
		return stream(COMMANDS) //
				.filter(command -> command.commandLineValue().equalsIgnoreCase(arguments[0])) //
				.findAny() //
				.orElseThrow(() -> new ParseException("Invalid command " + arguments[0]));
	}

	public void run() {
		command.run();
	}

}
