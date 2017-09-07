package org.cryptomator.sanitizer.restorer;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.Files.createDirectories;
import static java.nio.file.Files.exists;
import static java.nio.file.Files.readAllBytes;
import static java.util.stream.Collectors.toList;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.v1.DecryptingReadableByteChannel;

class ScannedVault {

	private static final Pattern ENCRYPTED_FILE_PATTERN = Pattern.compile("^[2-7A-Z]{2}/[2-7A-Z]{30}/((?:[2-7A-Z]{8})*[2-7A-Z=]{8})");
	private static final Pattern DIRECTORY_FILE_PATTERN = Pattern.compile("^[2-7A-Z]{2}/[2-7A-Z]{30}/0((?:[2-7A-Z]{8})*[2-7A-Z=]{8})");
	private static final Pattern LNG_FILE_PATTERN = Pattern.compile("^[2-7A-Z]{2}/[2-7A-Z]{30}/([2-7A-Z]{32})(.*)\\.lng");

	private final Cryptor cryptor;
	private final Path location;
	private final Path dDir;

	private final Map<String, EncryptedDirectoryBuilder> potentialRootsByHashedDirectoryId = new HashMap<>();
	private final Map<Path, EncryptedDirectoryBuilder> encryptedDirectoriesByPath = new HashMap<>();

	public ScannedVault(Cryptor cryptor, Path location) {
		this.cryptor = cryptor;
		this.location = location;
		this.dDir = location.resolve("d");
	}

	public void add(Path path) {
		Path relativeToDDir = dDir.relativize(path);
		String pathAsString = relativeToDDir.toString().toUpperCase().replace(File.separator, "/");
		@SuppressWarnings("unused")
		boolean ignored = addAsEncryptedDirectory(path, pathAsString) //
				|| addAsLngEncryptedFile(path, pathAsString) //
				|| addAsLngDirectoryFile(path, pathAsString) //
				|| addAsEncryptedFile(path, pathAsString) //
				|| addAsDirectoryFile(path, pathAsString) //
				|| addAsIgnoredFile(path, pathAsString);
	}

	private boolean addAsEncryptedDirectory(Path path, String pathAsString) {
		if (pathAsString.matches("[2-7A-Z]{2}/[2-7A-Z]{30}") && !encryptedDirectoriesByPath.containsKey(path)) {
			String directoryIdHash = pathAsString.replace("/", "");
			EncryptedDirectoryBuilder builder = new EncryptedDirectoryBuilder() //
					.withPath(path) //
					.withDirectoryIdHash(directoryIdHash);
			encryptedDirectoriesByPath.put(path, builder);
			potentialRootsByHashedDirectoryId.put(directoryIdHash, builder);
			return true;
		} else {
			return false;
		}
	}

	private boolean addAsEncryptedFile(Path path, String pathAsString) {
		Matcher matcher = ENCRYPTED_FILE_PATTERN.matcher(pathAsString);
		if (matcher.find()) {
			String encryptedName = matcher.group(1);
			String suffix = pathAsString.substring(matcher.end());
			EncryptedFile file = new EncryptedFile(path, encryptedName, suffix.isEmpty() ? Optional.empty() : Optional.of(suffix));
			encryptedDirectoriesByPath.get(path.getParent()).add(file);
			return true;
		} else {
			return false;
		}
	}

	private boolean addAsDirectoryFile(Path path, String pathAsString) {
		Matcher matcher = DIRECTORY_FILE_PATTERN.matcher(pathAsString);
		if (matcher.find()) {
			String directoryId;
			try {
				directoryId = new String(readAllBytes(path), UTF_8);
			} catch (IOException e) {
				throw new UncheckedIOException(e);
			}
			if (directoryId.equals("")) {
				return false;
			}
			addDirectoryFile(path, pathAsString, matcher.group(1), directoryId, pathAsString.substring(matcher.end()));
			return true;
		} else {
			return false;
		}
	}

	private boolean addAsLngEncryptedFile(Path path, String pathAsString) {
		Matcher matcher = LNG_FILE_PATTERN.matcher(pathAsString);
		if (matcher.find()) {
			String lngId = matcher.group(1);
			Path mFile = location.resolve("m").resolve(lngId.substring(0, 2)).resolve(lngId.substring(2, 4)).resolve(lngId + ".lng");
			if (Files.isRegularFile(mFile)) {
				try {
					String filename = new String(Files.readAllBytes(mFile), UTF_8);
					if (filename.startsWith("0")) {
						return false;
					}
					String suffix = matcher.group(2);
					EncryptedFile file = new EncryptedFile(path, filename, suffix.isEmpty() ? Optional.empty() : Optional.of(suffix));
					encryptedDirectoriesByPath.get(path.getParent()).add(file);
					return true;
				} catch (IOException e) {
					throw new UncheckedIOException(e);
				}
			}
			return false;
		} else {
			return false;
		}
	}

	private boolean addAsLngDirectoryFile(Path path, String pathAsString) {
		Matcher matcher = LNG_FILE_PATTERN.matcher(pathAsString);
		if (matcher.find()) {
			String lngId = matcher.group(1);
			Path mFile = location.resolve("m").resolve(lngId.substring(0, 2)).resolve(lngId.substring(2, 4)).resolve(lngId + ".lng");
			if (Files.isRegularFile(mFile)) {
				try {
					String filename = new String(Files.readAllBytes(mFile), UTF_8);
					if (!filename.startsWith("0")) {
						return false;
					}
					filename = filename.substring(1);
					String directoryId;
					try {
						directoryId = new String(readAllBytes(path), UTF_8);
					} catch (IOException e) {
						throw new UncheckedIOException(e);
					}
					if (directoryId.equals("")) {
						return false;
					}
					addDirectoryFile(path, pathAsString, filename, directoryId, matcher.group(2));
					return true;
				} catch (IOException e) {
					throw new UncheckedIOException(e);
				}
			}
			return false;
		} else {
			return false;
		}
	}

	private void addDirectoryFile(Path path, String pathAsString, String encryptedName, String directoryId, String suffix) {
		String directoryIdHash = cryptor.fileNameCryptor().hashDirectoryId(directoryId);
		EncryptedDirectoryBuilder directory = potentialRootsByHashedDirectoryId.remove(directoryIdHash);
		if (directory == null) {
			Path directoryPath = dDir.resolve(directoryIdHash.substring(0, 2)).resolve(directoryIdHash.substring(2));
			directory = new EncryptedDirectoryBuilder() //
					.withPath(directoryPath) //
					.withDirectoryIdHash(directoryIdHash);
			encryptedDirectoriesByPath.put(directoryPath, directory);
		}
		directory //
				.withDirectoryId(directoryId) //
				.withEncryptedName(encryptedName);
		if (!suffix.isEmpty())
			directory.withSuffix(suffix);
		encryptedDirectoriesByPath.get(path.getParent()).add(directory);
	}

	private boolean addAsIgnoredFile(Path path, String pathAsString) {
		if (encryptedDirectoriesByPath.containsKey(path)) {
			return false;
		}
		System.out.println("Ignoring " + pathAsString);
		return true;
	}

	public void decryptTo(Path targetLocation) {
		potentialRootsByHashedDirectoryId.values().stream() //
				.map(EncryptedDirectoryBuilder::build) //
				.forEach(root -> root.decryptTo(targetLocation));
	}

	private class EncryptedDirectory extends Entry {

		private List<Entry> entries;
		private Optional<String> directoryId = Optional.empty();

		public EncryptedDirectory(EncryptedDirectoryBuilder builder) {
			super(builder.path, builder.encryptedName, builder.suffix);
			this.directoryId = builder.directoryId;
			this.entries = builder.entries;
			this.entries.addAll(builder.builders.stream().map(EncryptedDirectoryBuilder::build).collect(toList()));
			entries.forEach(entry -> entry.setParent(this));
		}

		@Override
		public void tryDecryptTo(Path targetDirectory) throws IOException {
			Path target = determineTarget(targetDirectory);
			createDirectories(target);
			decryptContentsTo(target);
		}

		private Path determineTarget(Path targetDirectory) {
			if (isRealRoot()) {
				return targetDirectory.resolve("root");
			} else if (isRoot()) {
				Path lostAndFound = targetDirectory.resolve("lost+found");
				return nextFreeName(lostAndFound, "root", "");
			} else {
				String name = decryptedName().orElse("unknown-folder");
				return firstFreeName(targetDirectory, name, suffix.orElse(""));
			}
		}

		private void decryptContentsTo(Path targetDirectory) {
			System.out.println(dDir.relativize(path) + " -> " + targetDirectory);
			entries.forEach(entry -> entry.decryptTo(targetDirectory));
		}

		private boolean isRealRoot() {
			return directoryId.isPresent() && "".equals(directoryId.get());
		}

		private boolean isRoot() {
			return !parent.isPresent();
		}

	}

	public class EncryptedDirectoryBuilder {

		private Path path;
		private String encryptedName;
		private Optional<String> suffix = Optional.empty();
		private Optional<String> directoryId = Optional.empty();

		private List<EncryptedDirectoryBuilder> builders = new ArrayList<>();
		private List<Entry> entries = new ArrayList<>();

		public EncryptedDirectoryBuilder withPath(Path path) {
			this.path = path;
			return this;
		}

		public EncryptedDirectoryBuilder withDirectoryIdHash(String directoryIdHash) {
			if (cryptor.fileNameCryptor().hashDirectoryId("").equals(directoryIdHash)) {
				directoryId = Optional.of("");
			}
			return this;
		}

		public EncryptedDirectoryBuilder withEncryptedName(String encryptedName) {
			this.encryptedName = encryptedName;
			return this;
		}

		public EncryptedDirectoryBuilder withSuffix(String suffix) {
			this.suffix = Optional.of(suffix);
			return this;
		}

		public EncryptedDirectoryBuilder withDirectoryId(String directoryId) {
			this.directoryId = Optional.of(directoryId);
			return this;
		}

		public void add(EncryptedDirectoryBuilder builder) {
			builders.add(builder);
		}

		public void add(Entry entry) {
			entries.add(entry);
		}

		public EncryptedDirectory build() {
			return new EncryptedDirectory(this);
		}

	}

	private class EncryptedFile extends Entry {

		public EncryptedFile(Path path, String encryptedName, Optional<String> suffix) {
			super(path, encryptedName, suffix);
		}

		@Override
		public void tryDecryptTo(Path targetDirectory) throws IOException {
			String name = decryptedName().orElse("unknown-file");
			Path target = firstFreeName(targetDirectory, name, suffix.orElse(""));
			System.out.println(dDir.relativize(path) + " -> " + target);
			try (ReadableByteChannel readableByteChannel = Files.newByteChannel(path, StandardOpenOption.READ);
					ReadableByteChannel decryptingReadableByteChannel = new DecryptingReadableByteChannel(readableByteChannel, cryptor, true);
					WritableByteChannel writableByteChannel = Files.newByteChannel(target, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW)) {
				ByteBuffer buff = ByteBuffer.allocate(cryptor.fileContentCryptor().ciphertextChunkSize());
				while (decryptingReadableByteChannel.read(buff) != -1) {
					buff.flip();
					writableByteChannel.write(buff);
					buff.clear();
				}
			} catch (AuthenticationFailedException e) {
				System.out.println("Unable to decrypt: " + dDir.relativize(path) + ". AuthenticationFailedException: " + e.getMessage());
			}
		}

	}

	private abstract class Entry {

		final Path path;
		private final String encryptedName;
		final Optional<String> suffix;

		Optional<EncryptedDirectory> parent = Optional.empty();

		public Entry(Path path, String encryptedName, Optional<String> suffix) {
			this.path = path;
			this.encryptedName = encryptedName;
			this.suffix = suffix;
		}

		public void setParent(EncryptedDirectory parent) {
			this.parent = Optional.of(parent);
		}

		public Optional<String> decryptedName() {
			if (parent.isPresent() && parent.get().directoryId.isPresent()) {
				try {
					return Optional.of(cryptor.fileNameCryptor().decryptFilename(encryptedName, parent.get().directoryId.get().getBytes(UTF_8)));
				} catch (AuthenticationFailedException e) {
					System.out.println("Failed to authenticate name of " + dDir.relativize(path));
					return Optional.empty();
				}
			} else {
				return Optional.empty();
			}
		}

		public void decryptTo(Path targetDirectory) {
			try {
				tryDecryptTo(targetDirectory);
			} catch (IOException e) {
				throw new UncheckedIOException(e);
			}
		}

		public abstract void tryDecryptTo(Path targetDirectory) throws IOException;

	}

	private Path firstFreeName(Path dir, String prefix, String suffix) {
		Path result = dir.resolve(prefix + suffix);
		if (exists(result)) {
			return nextFreeName(dir, prefix, suffix);
		} else {
			return result;
		}
	}

	private Path nextFreeName(Path dir, String prefix, String suffix) {
		prefix += "-";
		int counter = 1;
		Path result;
		do {
			result = dir.resolve(prefix + counter++ + suffix);
		} while (exists(result));
		return result;
	}

}
