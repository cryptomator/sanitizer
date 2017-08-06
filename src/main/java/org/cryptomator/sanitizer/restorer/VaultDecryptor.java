package org.cryptomator.sanitizer.restorer;

import static java.nio.file.Files.walk;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.stream.Stream;

import org.cryptomator.cryptolib.Cryptors;
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
		Cryptor cryptor = provider.createFromKeyFile(keyFile, passphrase, keyFile.getVersion());
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

	/**
	 * TODO wtf! deduplicate code. See {@link FileDecryptor}, {@link PathEncryptor}.
	 * 
	 * @param keyFile
	 * @return
	 */
	private static CryptorProvider bestGuessCryptorProvider(KeyFile keyFile) {
		switch (keyFile.getVersion()) {
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
			return Cryptors.version1(strongSecureRandom());
		default:
			throw new IllegalArgumentException("Unsupported vault version " + keyFile.getVersion());
		}
	}

	private static SecureRandom strongSecureRandom() {
		try {
			return SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Java platform is required to support a strong SecureRandom.", e);
		}
	}

}
