package org.cryptomator.sanitizer.restorer;

import java.io.Console;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.cryptomator.cryptolib.api.Cryptor;

public class AutomaticCiphertextPathBuilder extends CiphertextPathBuilder {

	private final Path vaultRoot;

	protected AutomaticCiphertextPathBuilder(Path vaultRoot, Console console, Cryptor cryptor) {
		super(console, cryptor);
		this.vaultRoot = vaultRoot;
	}

	@Override
	protected String getDirectoryId(String directoryFilePath) {
		try {
			Path dirFile = vaultRoot.resolve(directoryFilePath);
			if (Files.isRegularFile(dirFile)) {
				return StandardCharsets.UTF_8.decode(ByteBuffer.wrap(Files.readAllBytes(dirFile))).toString();
			}
		} catch (IOException e) {
			// no-op
		}
		return console.readLine("Enter contents of missing file %s: ", directoryFilePath);
	}

}
