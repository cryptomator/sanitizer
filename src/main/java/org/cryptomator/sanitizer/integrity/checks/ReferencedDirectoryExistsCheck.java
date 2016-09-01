package org.cryptomator.sanitizer.integrity.checks;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.Files.isDirectory;
import static java.nio.file.Files.readAllBytes;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.sanitizer.integrity.problems.Problems;

class ReferencedDirectoryExistsCheck implements Check {

	private final Cryptor cryptor;
	private final Path pathToVault;

	public ReferencedDirectoryExistsCheck(Cryptor cryptor, Path pathToVault) {
		this.cryptor = cryptor;
		this.pathToVault = pathToVault;
	}

	@Override
	public void checkThrowingExceptions(Problems problems, Path dirfile) throws IOException {
		String directoryId = new String(readAllBytes(dirfile), UTF_8);
		String hashedDirectoryId = cryptor.fileNameCryptor().hashDirectoryId(directoryId);
		Path directory = pathToVault.resolve("d").resolve(hashedDirectoryId.substring(0, 2)).resolve(hashedDirectoryId.substring(2));
		if (!isDirectory(directory)) {
			problems.reportMissingDirectory(directory, dirfile, Files.exists(directory));
		}
	}

}
