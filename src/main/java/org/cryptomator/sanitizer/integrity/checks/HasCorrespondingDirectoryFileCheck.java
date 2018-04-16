package org.cryptomator.sanitizer.integrity.checks;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.sanitizer.integrity.problems.Problems;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.Files.readAllBytes;
import static java.nio.file.Files.walk;
import static java.util.regex.Pattern.CASE_INSENSITIVE;

public class HasCorrespondingDirectoryFileCheck implements Check {

	public static final String ROOT_DIRECTORY_ID = "";
	private final Pattern DIRECTORY_FILE_NAME_PATTERN = Pattern.compile("(0([A-Z2-7]{8})*[A-Z2-7=]{1,8})|([A-Z2-7]{32}\\.lng)", CASE_INSENSITIVE);
	private final Map<String, String> hashedToCleartextDirectoryIds = new HashMap<>();
	private boolean collectedReferencedDirectories = false;

	private final Cryptor cryptor;
	private final Path pathToVault;

	HasCorrespondingDirectoryFileCheck(Cryptor cryptor, Path pathToVault) {
		this.cryptor = cryptor;
		this.pathToVault = pathToVault;
	}

	@Override
	public void checkThrowingExceptions(Problems problems, Path path) throws IOException {
		collectReferencedDirectories();
		Path relativePath = pathToVault.resolve("d").relativize(path);
		String hashedDirectoryId = joinNamesWithoutSeparator(relativePath);
		if (!hashedToCleartextDirectoryIds.containsKey(hashedDirectoryId)) {
			problems.reportOrphanDirectory(path);
		}
	}

	public Optional<String> getCleartextId(String hashedId) {
		return Optional.ofNullable(hashedToCleartextDirectoryIds.get(hashedId));
	}

	private String joinNamesWithoutSeparator(Path relativePath) {
		StringBuilder result = new StringBuilder();
		relativePath.iterator().forEachRemaining(result::append);
		return result.toString().toUpperCase();
	}

	private void collectReferencedDirectories() throws IOException {
		if (collectedReferencedDirectories)
			return;
		hashedToCleartextDirectoryIds.put(cryptor.fileNameCryptor().hashDirectoryId(ROOT_DIRECTORY_ID), "");
		collectedReferencedDirectories = true;
		Path dFolder = pathToVault.resolve("d");
		Path mFolder = pathToVault.resolve("m");
		try (Stream<Path> files = walk(dFolder, 3)) {
			files.filter(Files::isRegularFile).forEach(file -> {
				String fileName = file.getFileName().toString();
				if (dFolder.relativize(file).getNameCount() == 3 && DIRECTORY_FILE_NAME_PATTERN.matcher(fileName).matches()) {
					addReferencedDirectoryFrom(file);
				}
			});
		}
		if (Files.isDirectory(mFolder)) {
			try (Stream<Path> files = walk(mFolder, 3)) {
				files.filter(Files::isRegularFile).forEach(file -> {
					String fileName = file.getFileName().toString();
					if (dFolder.relativize(file).getNameCount() == 3 && DIRECTORY_FILE_NAME_PATTERN.matcher(fileName).matches()) {
						addReferencedDirectoryFrom(file);
					}
				});
			}
		}
	}

	private void addReferencedDirectoryFrom(Path file) {
		try {
			if (Files.size(file) != 36)
				return;
			String directoryId = new String(readAllBytes(file), UTF_8);
			String hashedDirectoryId = cryptor.fileNameCryptor().hashDirectoryId(directoryId);
			hashedToCleartextDirectoryIds.put(hashedDirectoryId, directoryId);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

}
