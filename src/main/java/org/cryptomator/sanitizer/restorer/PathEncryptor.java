package org.cryptomator.sanitizer.restorer;

import static org.cryptomator.sanitizer.CryptorHolder.bestGuessCryptorProvider;
import static org.cryptomator.sanitizer.CryptorHolder.normalizePassphrase;

import java.io.Console;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;

import org.apache.commons.lang3.StringUtils;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.KeyFile;

public class PathEncryptor {

	public static void encryptPath(Path vaultLocation, CharSequence passphrase) throws IOException {
		Console console = System.console();
		if (console == null) {
			System.err.println("Couldn't get Console instance");
			return;
		}

		Path masterkeyPath = vaultLocation.resolve("masterkey.cryptomator");
		KeyFile keyFile = KeyFile.parse(Files.readAllBytes(masterkeyPath));
		CryptorProvider provider = bestGuessCryptorProvider(keyFile);
		Cryptor cryptor = provider.createFromKeyFile(keyFile, normalizePassphrase(keyFile, passphrase), keyFile.getVersion());

		Path filePath = resolvePath(vaultLocation, console, cryptor);
		console.printf("Resolved: %s\n", filePath);

		cryptor.destroy();
	}

	private static Path resolvePath(Path vaultRoot, Console console, Cryptor cryptor) throws NoSuchFileException {
		String cleartextPath = StringUtils.removeStart(console.readLine("Enter a (cleartext) path of a file inside the vault: "), "/");
		String ciphertextPath = new AutomaticCiphertextPathBuilder(vaultRoot, console, cryptor).resolve(cleartextPath);
		Path result = vaultRoot.resolve(ciphertextPath);
		if (Files.isRegularFile(result)) {
			return result;
		} else {
			throw new NoSuchFileException(result.toString());
		}
	}

}
