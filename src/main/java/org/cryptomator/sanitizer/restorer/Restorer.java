package org.cryptomator.sanitizer.restorer;

import java.io.Console;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.KeyFile;

public class Restorer {

	public static void main(String[] args) throws IOException {
		Console console = System.console();
		if (console == null) {
			System.out.println("Couldn't get Console instance");
			System.exit(1);
		}

		Path masterkeyPath = readMasterKeyPath(console);
		KeyFile keyFile = parseMasterKey(masterkeyPath);
		Cryptor cryptor = decryptKey(console, keyFile);
		Path filePath = resolvePath(masterkeyPath.getParent(), console, cryptor);
		console.printf("Resolved: %s", filePath);
	}

	private static Path readMasterKeyPath(Console console) {
		String path = console.readLine("Enter absolut path to masterkey.cryptomator:");
		Path masterKeyPath = Paths.get(path);
		if (Files.isRegularFile(masterKeyPath)) {
			return masterKeyPath;
		} else {
			throw new IllegalArgumentException("Invalid path");
		}
	}

	private static KeyFile parseMasterKey(Path masterkeyPath) throws IOException {
		try (ReadableByteChannel readable = Files.newByteChannel(masterkeyPath, StandardOpenOption.READ)) {
			ByteBuffer buf = ByteBuffer.allocate(1024); // 1kb should be sufficient for any known key version
			int size = readable.read(buf);
			byte[] serializedKey = new byte[size];
			buf.flip();
			buf.get(serializedKey);
			return KeyFile.parse(serializedKey);
		}
	}

	private static Cryptor decryptKey(Console console, KeyFile keyFile) {
		CryptorProvider provider = bestGuessCryptorProvider(keyFile);
		char[] passphrase = console.readPassword("Enter your passphrase:");
		try {
			return provider.createFromKeyFile(keyFile, CharBuffer.wrap(passphrase), keyFile.getVersion());
		} finally {
			Arrays.fill(passphrase, ' ');
		}
	}

	private static Path resolvePath(Path vaultRoot, Console console, Cryptor cryptor) throws NoSuchFileException {
		String cleartextPath = console.readLine("Enter a (cleartext) path:");
		String ciphertextPath = new ManualCiphertextPathBuilder(console, cryptor).resolve(cleartextPath);
		Path result = vaultRoot.resolve(ciphertextPath);
		if (Files.isRegularFile(result)) {
			return result;
		} else {
			throw new NoSuchFileException(result.toString());
		}
	}

	private static CryptorProvider bestGuessCryptorProvider(KeyFile keyFile) {
		switch (keyFile.getVersion()) {
		case 1:
		case 2:
		case 3:
		case 4:
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
