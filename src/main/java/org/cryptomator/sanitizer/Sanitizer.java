package org.cryptomator.sanitizer;

import java.io.PrintStream;

import org.cryptomator.sanitizer.commands.Commands;

public class Sanitizer {

	public static void main(String[] args) {
		System.out.println("# Cryptomator vault sanitizer v" + Version.get() + " #");
		System.out.println();
		Commands.parse(args).ifPresent(Sanitizer::main);
	}

	public static void main(Commands commands) {
		commands.run();
	}

	public static void print() {
		print(System.out);
	}

	public static void printNoNewline(String line) {
		printNoNewline(line, System.out);
	}

	public static void print(String line) {
		print(line, System.out);
	}

	public static void print(PrintStream s) {
		s.println();
	}

	public static void printNoNewline(String line, PrintStream s) {
		s.print(line);
	}

	public static void print(String line, PrintStream s) {
		s.println(line);
	}

}