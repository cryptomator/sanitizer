package org.cryptomator.sanitizer.restorer;

import static java.nio.file.Files.walk;
import static org.cryptomator.sanitizer.CryptorHolder.bestGuessCryptorProvider;
import static org.cryptomator.sanitizer.CryptorHolder.normalizePassphrase;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.KeyFile;
import org.cryptomator.sanitizer.Passphrase;

public class VaultDecryptor {

	private final Path vaultLocation;
	private final Path targetLocation;
	private final Passphrase passphrase;

	public VaultDecryptor(Path vaultLocation, Path targetLocation, Passphrase passphrase) throws IOException {
		this.vaultLocation = vaultLocation;
		this.targetLocation = targetLocation;
		this.passphrase = passphrase;
	}

	public void run() throws IOException {
		Path masterkeyPath = vaultLocation.resolve("masterkey.cryptomator");
		KeyFile keyFile = KeyFile.parse(Files.readAllBytes(masterkeyPath));
		CryptorProvider provider = bestGuessCryptorProvider(keyFile);
		Cryptor cryptor = provider.createFromKeyFile(keyFile, normalizePassphrase(keyFile, passphrase), keyFile.getVersion());
		try {
			ScannedVault vault = new ScannedVault(cryptor, vaultLocation);
			Path dDirectory = vaultLocation.resolve("d");
			try (Stream<Path> filesInVault = walk(dDirectory)) {
				filesInVault.forEach(path -> vault.add(path));
			}

			vault.decryptTo(targetLocation);
		} finally {
			cryptor.destroy();
		}
	}

}
