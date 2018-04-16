package org.cryptomator.sanitizer.integrity.checks;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.sanitizer.integrity.problems.NameNormalizationProblem.EncryptedNodeInfo;
import org.cryptomator.sanitizer.integrity.problems.Problems;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.Files.readAllBytes;
import static java.text.Normalizer.Form.NFC;
import static java.text.Normalizer.isNormalized;
import static org.cryptomator.sanitizer.utils.NameUtil.decryptablePartOfName;

class DecryptedNameCheck implements Check {

	private final Cryptor cryptor;
	private final HasCorrespondingDirectoryFileCheck hasCorrespondingDirectoryFileCheck;
	private final Optional<HasCorrespondingDFileCheck> hasCorrespondingDFileCheck;

	public DecryptedNameCheck(Cryptor cryptor, HasCorrespondingDirectoryFileCheck hasCorrespondingDirectoryFileCheck) {
		this.cryptor = cryptor;
		this.hasCorrespondingDirectoryFileCheck = hasCorrespondingDirectoryFileCheck;
		this.hasCorrespondingDFileCheck = Optional.empty();
	}

	public DecryptedNameCheck(Cryptor cryptor, HasCorrespondingDirectoryFileCheck hasCorrespondingDirectoryFileCheck, HasCorrespondingDFileCheck hasCorrespondingDFileCheck) {
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
			Optional<Path> dFile = hasCorrespondingDFileCheck.get().pathOfDFile(path);
			Optional<String> optionalDirectoryId = dFile
					.map(this::hashedDirectoryIdForFileInDirectory)
					.flatMap(hasCorrespondingDirectoryFileCheck::getCleartextId);
			optionalDirectoryId.ifPresent(directoryId -> {
				checkEncryptedName(directoryId, decryptablePartOfName.get(), problems, dFile.get(), Optional.of(path));
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
				checkEncryptedName(directoryId, decryptablePartOfName.get(), problems, path, Optional.empty());
			});
		} else {
			problems.reportNameProblem("name with decryptable part", path);
		}
	}

	private void checkEncryptedName(String directoryId, String decryptablePartOfName, Problems problems, Path path, Optional<Path> mFile) {
		Optional<String> decryptedName = decrypt(directoryId, decryptablePartOfName);
		if (decryptedName.isPresent()) {
			if (!isNormalized(decryptedName.get(), NFC)) {
				problems.reportNameNormalizationProblem(new EncryptedNodeInfo(path, directoryId, mFile));
			}
		} else if (mFile.isPresent()) {
			problems.reportFileContentProblem(mFile.get(), "a decryptable name", "");
		} else {
			problems.reportNameProblem("a decryptable name", path);
		}
	}

	private Optional<String> decrypt(String directoryId, String name) {
		try {
			return Optional.of(cryptor.fileNameCryptor().decryptFilename(name, directoryId.getBytes(StandardCharsets.UTF_8)));
		} catch (AuthenticationFailedException e) {
			return Optional.empty();
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
