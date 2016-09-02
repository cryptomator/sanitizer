package org.cryptomator.sanitizer.integrity.checks;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.Files.readAllBytes;
import static org.cryptomator.sanitizer.utils.NameUtil.decryptablePartOfName;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Optional;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.sanitizer.integrity.problems.Problems;

class NameIsDecryptableCheck implements Check {

	private final Cryptor cryptor;
	private final HasCorrespondingDirectoryFileCheck hasCorrespondingDirectoryFileCheck;
	private final Optional<HasCorrespondingDFileCheck> hasCorrespondingDFileCheck;

	public NameIsDecryptableCheck(Cryptor cryptor, HasCorrespondingDirectoryFileCheck hasCorrespondingDirectoryFileCheck) {
		this.cryptor = cryptor;
		this.hasCorrespondingDirectoryFileCheck = hasCorrespondingDirectoryFileCheck;
		this.hasCorrespondingDFileCheck = Optional.empty();
	}

	public NameIsDecryptableCheck(Cryptor cryptor, HasCorrespondingDirectoryFileCheck hasCorrespondingDirectoryFileCheck, HasCorrespondingDFileCheck hasCorrespondingDFileCheck) {
		this.cryptor = cryptor;
		this.hasCorrespondingDirectoryFileCheck = hasCorrespondingDirectoryFileCheck;
		this.hasCorrespondingDFileCheck = Optional.of(hasCorrespondingDFileCheck);
	}

	@Override
	public void checkThrowingExceptions(Problems problems, Path path) throws IOException {
		if (hasCorrespondingDFileCheck.isPresent()) {
			checkLongFileOrDirectory(problems, path);
		} else {
			checkRegularFileOrDirectory(problems, path);
		}
	}

	private void checkLongFileOrDirectory(Problems problems, Path path) throws IOException {
		Optional<String> decryptablePartOfName = decryptablePartOfName(new String(readAllBytes(path), UTF_8));
		if (decryptablePartOfName.isPresent()) {
			Optional<String> optionalDirectoryId = hasCorrespondingDFileCheck.get().pathOfDFile(path.getFileName().toString()) //
					.map(this::hashedDirectoryIdForFileInDirectory) //
					.flatMap(hasCorrespondingDirectoryFileCheck::getCleartextId);
			optionalDirectoryId.ifPresent(directoryId -> {
				if (!isDecryptable(directoryId, decryptablePartOfName.get())) {
					problems.reportFileContentProblem(path, "a decryptable name", "");
				}
			});
		} else {
			problems.reportFileContentProblem(path, "name with decryptable part", "");
		}
	}

	private void checkRegularFileOrDirectory(Problems problems, Path path) {
		Optional<String> decryptablePartOfName = decryptablePartOfName(path.getFileName().toString());
		if (decryptablePartOfName.isPresent()) {
			Optional<String> optionalDirectoryId = hasCorrespondingDirectoryFileCheck.getCleartextId(hashedDirectoryIdForFileInDirectory(path));
			optionalDirectoryId.ifPresent(directoryId -> {
				if (!isDecryptable(directoryId, decryptablePartOfName.get())) {
					problems.reportNameProblem("a decryptable name", path);
				}
			});
		} else {
			problems.reportNameProblem("name with decryptable part", path);
		}
	}

	private boolean isDecryptable(String directoryId, String name) {
		try {
			cryptor.fileNameCryptor().decryptFilename(name, directoryId.getBytes(StandardCharsets.UTF_8));
			return true;
		} catch (AuthenticationFailedException e) {
			return false;
		}
	}

	private String hashedDirectoryIdForFileInDirectory(Path path) {
		Path parent = path.getParent();
		Path parentsParent = parent.getParent();
		String result = parentsParent.getFileName().toString() + parent.getFileName().toString();
		result = result.toUpperCase();
		return result;
	}

}
