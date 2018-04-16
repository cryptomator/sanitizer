package org.cryptomator.sanitizer.integrity.checks;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.KeyFile;

import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.Files.readAllBytes;
import static java.nio.file.StandardOpenOption.READ;
import static java.util.regex.Pattern.CASE_INSENSITIVE;
import static org.cryptomator.sanitizer.integrity.checks.HasCorrespondingDirectoryFileCheck.ROOT_DIRECTORY_ID;

public class Checks {

	static final long MAX_NAME_LENGTH = 10000;

	public static CompoundFileCheck file() {
		return new CompoundFileCheck();
	}

	public static CompoundDirectoryCheck dir() {
		return new CompoundDirectoryCheck();
	}

	public static Check hasName(String stringPattern) {
		Pattern pattern = Pattern.compile(stringPattern, CASE_INSENSITIVE);
		return (problems, path) -> {
			String filename = path.getFileName().toString();
			if (!pattern.matcher(filename).matches()) {
				problems.reportNameProblem('^' + stringPattern + '$', path);
			}
		};
	}

	public static Check nameDoesNotContainLowercaseChars() {
		return new NameDoesNotContainLowercaseCharsCheck();
	}

	public static Check nameDoesNotContainUppercaseChars() {
		return (problems, path) -> {
			String filename = path.getFileName().toString();
			for (char c : filename.toCharArray()) {
				if (Character.isUpperCase(c)) {
					problems.reportUppercasedFile(path);
					return;
				}
			}
		};
	}

	public static Check containsValidName() {
		return contains("a valid name", "0?([A-Z2-7]{8}){2,}[A-Z2-7=]{8}", MAX_NAME_LENGTH);
	}

	public static Check containsValidFileName() {
		return contains("a valid name", "([A-Z2-7]{8}){2,}[A-Z2-7=]{8}", MAX_NAME_LENGTH);
	}

	public static Check containsValidDirectoryFileName() {
		return contains("a valid name", "0([A-Z2-7]{8}){2,}[A-Z2-7=]{8}", MAX_NAME_LENGTH);
	}

	public static Check isMasterkeyBackupFile() {
		return (problems, path) -> {
			try {
				KeyFile.parse(readAllBytes(path));
			} catch (IllegalArgumentException e) {
				problems.reportInvalidMasterkeyBackupFile(path);
			}
		};
	}

	private static Check contains(String description, String pattern, long maxLength) {
		return (problems, path) -> {
			if (Files.size(path) > maxLength) {
				problems.reportFileContentProblem(path, description, "a value longer " + maxLength + " bytes");
			}
			String name = new String(readAllBytes(path), UTF_8);
			if (!name.matches(pattern)) {
				problems.reportFileContentProblem(path, description, name);
			}
		};
	}

	public static Check containsUuid() {
		return (problems, path) -> {
			ByteBuffer bytes = ByteBuffer.wrap(new byte[36]);
			try (FileChannel in = FileChannel.open(path, READ)) {
				while (bytes.hasRemaining()) {
					if (in.read(bytes) == -1)
						break;
				}
			}
			String uuid = new String(bytes.array(), UTF_8);
			if (!uuid.matches("[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}")) {
				problems.reportFileContentProblem(path, "a uuid", uuid);
			}
		};
	}

	public static Check isAuthentic(Cryptor cryptor, boolean alsoCheckContent) {
		return new AuthenticationCheck(cryptor, alsoCheckContent);
	}

	public static Check hasSize(long size) {
		return (problems, path) -> {
			long fileSize = Files.size(path);
			if (fileSize != size) {
				problems.reportSizeMismatch(path, "= " + size, fileSize);
			}
		};
	}

	public static Check hasMinSize(long minSize) {
		return (problems, path) -> {
			long fileSize = Files.size(path);
			if (fileSize < minSize) {
				problems.reportSizeMismatch(path, ">= " + minSize, fileSize);
			}
		};
	}

	public static Check emptyEncryptedFileIfEmpty() {
		return (problems, path) -> {
			long fileSize = Files.size(path);
			if (fileSize == 88) {
				problems.reportEmptyEncryptedFile(path);
			}
		};
	}

	public static HasCorrespondingDFileCheck hasCorrespondingDFileIn(Path pathToVault) {
		return new HasCorrespondingDFileCheck(pathToVault);
	}

	public static HasCorrespondingMFileCheck hasCorrespondingMFileIn(Path pathToVault) {
		return new HasCorrespondingMFileCheck(pathToVault);
	}

	public static Check aConflict() {
		return (problems, path) -> {
			problems.reportConflict(path);
		};
	}

	public static Check aFileWithMissingEqualsSign() {
		return (problems, path) -> {
			problems.reportFileWithMissingEqualsSign(path);
		};
	}

	public static Check referencedDirectoryExists(Cryptor cryptor, Path pathToVault) {
		return new ReferencedDirectoryExistsCheck(cryptor, pathToVault);
	}

	public static HasCorrespondingDirectoryFileCheck hasCorrespondingDirectoryFile(Cryptor cryptor, Path pathToVault) {
		return new HasCorrespondingDirectoryFileCheck(cryptor, pathToVault);
	}

	public static Check rootDirectoryIfMachting(Cryptor cryptor) {
		String hashedRootDirectoryId = cryptor.fileNameCryptor().hashDirectoryId(ROOT_DIRECTORY_ID);
		return (problems, path) -> {
			String hashedDirectoryId = path.getParent().getFileName().toString() + path.getFileName();
			if (hashedDirectoryId.equals(hashedRootDirectoryId)) {
				problems.reportRootDirectoryExists(path);
			}
		};
	}

	public static Check decryptedNameCheck(Cryptor cryptor, HasCorrespondingDirectoryFileCheck hasCorrespondingDirectoryFileCheck) {
		return new DecryptedNameCheck(cryptor, hasCorrespondingDirectoryFileCheck);
	}

	public static Check decryptedNameCheck(Cryptor cryptor, HasCorrespondingDirectoryFileCheck hasCorrespondingDirectoryFileCheck, HasCorrespondingDFileCheck hasCorrespondingDFileCheck) {
		return new DecryptedNameCheck(cryptor, hasCorrespondingDirectoryFileCheck, hasCorrespondingDFileCheck);
	}

}
