package org.cryptomator.sanitizer.commands;

import org.apache.commons.cli.ParseException;

public interface Command {

	String commandLineValue();

	void printUsage();

	void parse(String[] arguments) throws ParseException;

	void run();

}
