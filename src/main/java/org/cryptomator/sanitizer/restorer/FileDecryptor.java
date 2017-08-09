package org.cryptomator.sanitizer.restorer;

import static org.cryptomator.sanitizer.CryptorHolder.bestGuessCryptorProvider;
import static org.cryptomator.sanitizer.CryptorHolder.normalizePassphrase;

import java.io.Console;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.KeyFile;
import org.cryptomator.cryptolib.v1.DecryptingReadableByteChannel;

public class FileDecryptor {

	public static void decryptFile(Path vaultLocation, CharSequence passphrase) throws IOException {
		Console console = System.console();
		if (console == null) {
			System.err.println("Couldn't get Console instance");
			return;
		}

		Path masterkeyPath = vaultLocation.resolve("masterkey.cryptomator");
		KeyFile keyFile = KeyFile.parse(Files.readAllBytes(masterkeyPath));
		Path ciphertextPath = getCiphertextPathFromUser(console);
		Path outputPath = getOutputPathFromUser(console);

		CryptorProvider provider = bestGuessCryptorProvider(keyFile);
		Cryptor cryptor = provider.createFromKeyFile(keyFile, normalizePassphrase(keyFile, passphrase), keyFile.getVersion());
		try (ReadableByteChannel readableByteChannel = Files.newByteChannel(ciphertextPath, StandardOpenOption.READ);
				ReadableByteChannel decryptingReadableByteChannel = new DecryptingReadableByteChannel(readableByteChannel, cryptor, true);
				WritableByteChannel writableByteChannel = Files.newByteChannel(outputPath, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW)) {
			ByteBuffer buff = ByteBuffer.allocate(cryptor.fileContentCryptor().ciphertextChunkSize());
			while (decryptingReadableByteChannel.read(buff) != -1) {
				buff.flip();
				writableByteChannel.write(buff);
				buff.clear();
			}
		} finally {
			cryptor.destroy();
		}

		console.printf("File successfully decrypted.\n");
	}

	private static Path getCiphertextPathFromUser(Console console) throws NoSuchFileException {
		String ciphertextPath = console.readLine("Enter absolute path of an encrypted file: ");
		Path result = Paths.get(ciphertextPath);
		if (!result.isAbsolute()) {
			throw new IllegalArgumentException("Given path is not absolute.");
		} else if (Files.isRegularFile(result)) {
			return result;
		} else {
			throw new NoSuchFileException("No such file: " + result.toString());
		}
	}

	private static Path getOutputPathFromUser(Console console) throws NoSuchFileException {
		String outputPath = console.readLine("Enter absolute path of decrypted output: ");
		Path result = Paths.get(outputPath);
		if (!result.isAbsolute()) {
			throw new IllegalArgumentException("Given path is not absolute.");
		} else {
			return result;
		}
	}

}
