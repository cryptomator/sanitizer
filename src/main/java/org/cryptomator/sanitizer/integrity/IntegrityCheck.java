package org.cryptomator.sanitizer.integrity;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.sanitizer.CryptorHolder;
import org.cryptomator.sanitizer.integrity.checks.Check;
import org.cryptomator.sanitizer.integrity.checks.Checks;
import org.cryptomator.sanitizer.integrity.checks.HasCorrespondingDFileCheck;
import org.cryptomator.sanitizer.integrity.checks.HasCorrespondingDirectoryFileCheck;
import org.cryptomator.sanitizer.integrity.problems.Problem;
import org.cryptomator.sanitizer.integrity.problems.Problems;

import java.nio.file.Path;
import java.util.Set;

import static org.cryptomator.sanitizer.integrity.checks.Checks.*;

public class IntegrityCheck {

	private final CryptorHolder cryptorHolder;

	public IntegrityCheck(CryptorHolder cryptorHolder) {
		this.cryptorHolder = cryptorHolder;
	}

	public Set<Problem> check(Path path, CharSequence passphrase, boolean checkFileIntegrity) throws AbortCheckException {
		Problems problems = new Problems(path);
		try {
			cryptorHolder.createCryptor(problems, path, passphrase).ifPresent(cryptor -> {
				try {
					vaultFormatChecks(cryptor, path, checkFileIntegrity).check(problems, path);
				} finally {
					cryptor.destroy();
				}
			});
		} catch (AbortCheckException e) {
			throw e;
		} catch (Exception e) {
			problems.reportException(e);
		}
		return problems.asSet();
	}

	private Check vaultFormatChecks(Cryptor cryptor, Path pathToVault, boolean checkContentIntegrity) {
		Check referencedDirectoryExists = referencedDirectoryExists(cryptor, pathToVault);
		HasCorrespondingDirectoryFileCheck hasCorrespondingDirectoryFileCheck = hasCorrespondingDirectoryFile(cryptor, pathToVault);
		Check decryptedNameCheckForRegularFiles = decryptedNameCheck(cryptor, hasCorrespondingDirectoryFileCheck);
		HasCorrespondingDFileCheck hasCorrespondingDFile = hasCorrespondingDFileIn(pathToVault);
		Check decryptedNameCheckForLongFiles = Checks.decryptedNameCheck(cryptor, hasCorrespondingDirectoryFileCheck, hasCorrespondingDFile);
		Check emptyEncryptedFileIfEmpty = emptyEncryptedFileIfEmpty();
		return dir().containing( //
				dir().that(hasName("d")).validate(nameDoesNotContainUppercaseChars()).containing( //
						dir().that(hasName("[A-Z2-7]{2}")).validate(nameDoesNotContainLowercaseChars()).containing( //
								dir().that(hasName("[A-Z2-7]{30}")) //
										.validate(nameDoesNotContainLowercaseChars()).validate(hasCorrespondingDirectoryFileCheck) //
										.reportAs(rootDirectoryIfMachting(cryptor)) //
										.containing( //
												file().that(hasName("0([A-Z2-7]{8})*[A-Z2-7=]{8}")) //
														.validate(nameDoesNotContainLowercaseChars()) //
														.validate(hasSize(36).and(containsUuid()).and(referencedDirectoryExists)) //
														.validate(decryptedNameCheckForRegularFiles), //
												file().that(hasName("([A-Z2-7]{8})*[A-Z2-7=]{8}")) //
														.reportAs(emptyEncryptedFileIfEmpty) //
														.validate(nameDoesNotContainLowercaseChars()) //
														.validate(hasMinSize(88).and(isAuthentic(cryptor, checkContentIntegrity))) //
														.validate(decryptedNameCheckForRegularFiles), //
												file().that(hasName("[A-Z2-7]{32}\\.lng").and(hasCorrespondingMFileIn(pathToVault).that(containsValidFileName()))) //
														.reportAs(emptyEncryptedFileIfEmpty) //
														.validate(nameDoesNotContainLowercaseChars()) //
														.validate(hasMinSize(88).and(isAuthentic(cryptor, checkContentIntegrity))), //
												file().that(hasName("[A-Z2-7]{32}\\.lng").and(hasCorrespondingMFileIn(pathToVault).that(containsValidDirectoryFileName()))) //
														.validate(nameDoesNotContainLowercaseChars()) //
														.validate(hasSize(36).and(containsUuid()).and(referencedDirectoryExists)), //
												file().that(hasName("[A-Z2-7]{32}\\.lng")) //
														.validate(nameDoesNotContainLowercaseChars()) //
														.validate(hasCorrespondingMFileIn(pathToVault)), //
												file().that(hasName("0?([A-Z2-7]{8})*[A-Z2-7=]{1,7}")) //
														.validate(nameDoesNotContainLowercaseChars()) //
														.validate(hasSize(36).and(containsUuid()).and(referencedDirectoryExists)) //
														.validate(decryptedNameCheckForRegularFiles) //
														.reportAs(aFileWithMissingEqualsSign()), //
												file().that(hasName("0([A-Z2-7]{8})*[A-Z2-7=]{8}.+")) //
														.validate(nameDoesNotContainLowercaseChars()) //
														.validate(hasSize(36).and(containsUuid()).and(referencedDirectoryExists)) //
														.validate(decryptedNameCheckForRegularFiles) //
														.reportAs(aConflict()), //
												file().that(hasName("([A-Z2-7]{8})*[A-Z2-7=]{8}.+")) //
														.reportAs(emptyEncryptedFileIfEmpty) //
														.validate(nameDoesNotContainLowercaseChars()) //
														.validate(hasMinSize(88).and(isAuthentic(cryptor, checkContentIntegrity))) //
														.validate(decryptedNameCheckForRegularFiles) //
														.reportAs(aConflict()), //
												file().that(hasName("[A-Z2-7]{32}.+\\.lng")) //
														.validate(nameDoesNotContainLowercaseChars()) //
														.validate(hasCorrespondingMFileIn(pathToVault)) //
														.reportAs(aConflict())))), //
				dir().that(hasName("m")).validate(nameDoesNotContainUppercaseChars()).containing( //
						dir().that(hasName("[A-Z2-7]{2}")).validate(nameDoesNotContainLowercaseChars()).containing( //
								dir().that(hasName("[A-Z2-7]{2}")).validate(nameDoesNotContainLowercaseChars()).containing( //
										file().that(hasName("[A-Z2-7]{32}\\.lng")) //
												.validate(nameDoesNotContainLowercaseChars()) //
												.validate(hasCorrespondingDFile.and(containsValidName()))
												.validate(decryptedNameCheckForLongFiles), //
										file().that(hasName("[A-Z2-7]{32}.+\\.lng")) //
												.validate(nameDoesNotContainLowercaseChars()) //
												.validate(hasCorrespondingDFile.and(containsValidName())) //
												.validate(decryptedNameCheckForLongFiles)
												.reportAs(aConflict())))), //
				file().that(hasName("masterkey.cryptomator")).validate(nameDoesNotContainUppercaseChars()), // do not validate contents because this already happened when creating the Cryptor
				file().that(hasName("masterkey.cryptomator.bkup")).validate(isMasterkeyBackupFile()));
	}

}
