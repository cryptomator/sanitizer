package org.cryptomator.sanitizer.restorer;

import static org.cryptomator.sanitizer.CryptorHolder.bestGuessCryptorProvider;
import static org.cryptomator.sanitizer.CryptorHolder.normalizePassphrase;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.*;

import org.apache.commons.lang3.StringUtils;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.KeyFile;

public class PathEncryptor {

	public static void encryptPath(Path vaultLocation, CharSequence passphrase, List<String> cleartextList, String outputPath) throws IOException {
		Console console = System.console();
		if (console == null) {
			System.err.println("Couldn't get Console instance");
			return;
		}

		Path masterkeyPath = vaultLocation.resolve("masterkey.cryptomator");
		KeyFile keyFile = KeyFile.parse(Files.readAllBytes(masterkeyPath));
		CryptorProvider provider = bestGuessCryptorProvider(keyFile);
		Cryptor cryptor = provider.createFromKeyFile(keyFile, normalizePassphrase(keyFile, passphrase), keyFile.getVersion());

		Map<String,Path> paths = new HashMap<>();
		if (cleartextList != null) {
			for (String path : cleartextList) {
				paths.put(path, null);
			}
		} else {
			String cleartextPath = StringUtils.removeStart(console.readLine("Enter a (cleartext) path of a file inside the vault: "), "/");
			paths.put(cleartextPath, null);
		}

		for (Map.Entry entry : paths.entrySet()) {
			try {
				entry.setValue(resolvePath(vaultLocation, console, cryptor, (String) entry.getKey()));
			} catch (NoSuchFileException e) {
				// entry.value will remain null and will be handled at a later point.
			}
		}

		printResolvedPaths(console, paths, outputPath);

		cryptor.destroy();
	}

	private static Path resolvePath(Path vaultRoot, Console console, Cryptor cryptor, String cleartextPath) throws NoSuchFileException {
		String ciphertextPath = new CiphertextPathBuilder(vaultRoot, console, cryptor).resolve(cleartextPath);
		Path result = vaultRoot.resolve(ciphertextPath);
		if (Files.isRegularFile(result)) {
			return result;
		} else {
			throw new NoSuchFileException(result.toString());
		}
	}

	private static void printResolvedPaths(Console console, Map<String, Path> paths, String outputPath) throws IOException {
		if (outputPath != null) {
			try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputPath))) {
				String line;
				for (Map.Entry entry : paths.entrySet()) {
					if (outputPath.endsWith(".csv")) {
						line = String.format("\"%s\",\"%s\"", entry.getKey(), entry.getValue());
					} else {
						line = String.format("%s: %s", entry.getKey(), entry.getValue());
					}
					writer.write(line + "\n");
				}
			}
		} else {
			for (Map.Entry entry : paths.entrySet()) {
				console.printf("%s: %s\n", entry.getKey(), entry.getValue());
				console.flush();
			}
		}
	}

}
