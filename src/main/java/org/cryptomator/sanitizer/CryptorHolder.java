package org.cryptomator.sanitizer;

import static java.lang.String.format;
import static java.nio.file.Files.isRegularFile;
import static java.nio.file.Files.readAllBytes;

import java.io.IOException;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.text.Normalizer.Form;
import java.util.Optional;

import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.cryptolib.api.KeyFile;
import org.cryptomator.sanitizer.integrity.AbortCheckException;
import org.cryptomator.sanitizer.integrity.problems.Problems;

public class CryptorHolder implements AutoCloseable {

	private static final int VAULT_VERSION = 6;

	private static final int VAULT_VERSION_INTRODUCING_PASSWORD_NORMALIZATION = 6;

	private Optional<Cryptor> cryptor = Optional.empty();

	public Optional<Cryptor> optionalCryptor() {
		return cryptor;
	}

	public Optional<Cryptor> createCryptor(Problems problems, Path path, CharSequence passphrase) throws IOException, AbortCheckException {
		destroyCryptor();
		Path masterkeyFile = path.resolve("masterkey.cryptomator");
		try {
			if (!isRegularFile(masterkeyFile)) {
				problems.reportMissingMasterkeyFile(masterkeyFile);
				return Optional.empty();
			}
			KeyFile keyFile = KeyFile.parse(readAllBytes(masterkeyFile));
			if (keyFile.getVersion() != VAULT_VERSION) {
				throw new AbortCheckException(format("Vault version mismatch. Expected: %d Actual: %d", VAULT_VERSION, keyFile.getVersion()));
			}
			cryptor = Optional.of(bestGuessCryptorProvider(keyFile).createFromKeyFile(keyFile, normalizePassphrase(keyFile, passphrase), keyFile.getVersion()));
			return cryptor;
		} catch (InvalidPassphraseException e) {
			throw new AbortCheckException("Invalid passphrase");
		} catch (IllegalArgumentException e) {
			if (e.getCause() instanceof InvalidKeyException) {
				throw new AbortCheckException("JCE files seem to be missing. Download from \n" //
						+ "http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html.\n" //
						+ "and install according to instructions in README.txt");
			} else {
				problems.reportInvalidMasterkeyFile(masterkeyFile);
			}
		}
		cryptor = Optional.empty();
		return cryptor;
	}

	public void destroyCryptor() {
		cryptor.ifPresent(Cryptor::destroy);
	}

	@Override
	public void close() {
		destroyCryptor();
	}

	public static CharSequence normalizePassphrase(KeyFile keyFile, CharSequence passphrase) {
		if (keyFile.getVersion() < VAULT_VERSION_INTRODUCING_PASSWORD_NORMALIZATION) {
			return passphrase;
		}
		return Normalizer.normalize(passphrase, Form.NFC);
	}

	public static CryptorProvider bestGuessCryptorProvider(KeyFile keyFile) {
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
