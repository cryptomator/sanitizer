package org.cryptomator.sanitizer.restorer;

import java.io.Console;

import org.cryptomator.cryptolib.api.Cryptor;

public class ManualCiphertextPathBuilder extends CiphertextPathBuilder {

	public ManualCiphertextPathBuilder(Console console, Cryptor cryptor) {
		super(console, cryptor);
	}

	@Override
	protected String getDirectoryId(String directoryFilePath) {
		System.out.println("Enter contents of file " + directoryFilePath);
		return console.readLine("Enter contents of file %s:", directoryFilePath);
	}

}
