package org.cryptomator.sanitizer.restorer;

import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.cryptomator.cryptolib.api.Cryptor;

public abstract class CiphertextPathBuilder {

	protected final Cryptor cryptor;
	protected final Console console;

	protected CiphertextPathBuilder(Console console, Cryptor cryptor) {
		this.console = console;
		this.cryptor = cryptor;
	}

	public String resolve(String absoluteCleartextPath) {
		return resolve("", absoluteCleartextPath.split("\\/"));
	}

	private String resolve(String directoryId, String... cleartextPathFragments) {
		if (cleartextPathFragments.length < 1) {
			throw new IllegalArgumentException("cleartextPathFragments must not be empty");
		} else if (cleartextPathFragments.length == 1) {
			String ciphertextFileName = cryptor.fileNameCryptor().encryptFilename(cleartextPathFragments[0], directoryId.getBytes(StandardCharsets.UTF_8));
			return getPath(directoryId, ciphertextFileName);
		} else {
			String ciphertextFileName = cryptor.fileNameCryptor().encryptFilename(cleartextPathFragments[0], directoryId.getBytes(StandardCharsets.UTF_8));
			String directoryFilePath = getPath(directoryId, "0" + ciphertextFileName);
			String subDirectoryId = getDirectoryId(directoryFilePath);
			String[] remainingCleartextPathFragments = Arrays.copyOfRange(cleartextPathFragments, 1, cleartextPathFragments.length);
			assert remainingCleartextPathFragments.length == cleartextPathFragments.length - 1;
			return resolve(subDirectoryId, remainingCleartextPathFragments);
		}
	}

	protected abstract String getDirectoryId(String directoryFilePath);

	protected String getPath(String directoryId, String ciphertextFileName) {
		String hashedDir = cryptor.fileNameCryptor().hashDirectoryId(directoryId);
		return "d/" + hashedDir.substring(0, 2) + "/" + hashedDir.substring(2) + "/" + ciphertextFileName;
	}

}
