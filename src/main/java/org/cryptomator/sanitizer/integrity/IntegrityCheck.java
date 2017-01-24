package org.cryptomator.sanitizer.integrity;

import static org.cryptomator.sanitizer.integrity.checks.Checks.aConflict;
import static org.cryptomator.sanitizer.integrity.checks.Checks.aFileWithMissingEqualsSign;
import static org.cryptomator.sanitizer.integrity.checks.Checks.containsUuid;
import static org.cryptomator.sanitizer.integrity.checks.Checks.containsValidDirectoryFileName;
import static org.cryptomator.sanitizer.integrity.checks.Checks.containsValidFileName;
import static org.cryptomator.sanitizer.integrity.checks.Checks.containsValidName;
import static org.cryptomator.sanitizer.integrity.checks.Checks.dir;
import static org.cryptomator.sanitizer.integrity.checks.Checks.emptyEncryptedFileIfEmpty;
import static org.cryptomator.sanitizer.integrity.checks.Checks.file;
import static org.cryptomator.sanitizer.integrity.checks.Checks.hasCorrespondingDFileIn;
import static org.cryptomator.sanitizer.integrity.checks.Checks.hasCorrespondingDirectoryFile;
import static org.cryptomator.sanitizer.integrity.checks.Checks.hasCorrespondingMFileIn;
import static org.cryptomator.sanitizer.integrity.checks.Checks.hasMinSize;
import static org.cryptomator.sanitizer.integrity.checks.Checks.hasName;
import static org.cryptomator.sanitizer.integrity.checks.Checks.hasSize;
import static org.cryptomator.sanitizer.integrity.checks.Checks.isAuthentic;
import static org.cryptomator.sanitizer.integrity.checks.Checks.isMasterkeyBackupFile;
import static org.cryptomator.sanitizer.integrity.checks.Checks.nameDoesNotContainLowercaseChars;
import static org.cryptomator.sanitizer.integrity.checks.Checks.nameDoesNotContainUppercaseChars;
import static org.cryptomator.sanitizer.integrity.checks.Checks.nameIsDecryptable;
import static org.cryptomator.sanitizer.integrity.checks.Checks.referencedDirectoryExists;
import static org.cryptomator.sanitizer.integrity.checks.Checks.rootDirectoryIfMachting;

import java.nio.file.Path;
import java.util.Set;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.sanitizer.CryptorHolder;
import org.cryptomator.sanitizer.integrity.checks.Check;
import org.cryptomator.sanitizer.integrity.checks.HasCorrespondingDirectoryFileCheck;
import org.cryptomator.sanitizer.integrity.problems.Problem;
import org.cryptomator.sanitizer.integrity.problems.Problems;

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
		Check nameIsDecryptable = nameIsDecryptable(cryptor, hasCorrespondingDirectoryFileCheck);
		Check hasCorrespondingDFile = hasCorrespondingDFileIn(pathToVault);
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
														.validate(nameIsDecryptable), //
												file().that(hasName("([A-Z2-7]{8})*[A-Z2-7=]{8}")) //
														.reportAs(emptyEncryptedFileIfEmpty) //
														.validate(nameDoesNotContainLowercaseChars()) //
														.validate(hasMinSize(88).and(isAuthentic(cryptor, checkContentIntegrity))) //
														.validate(nameIsDecryptable), //
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
														.validate(nameIsDecryptable) //
														.reportAs(aFileWithMissingEqualsSign()), //
												file().that(hasName("0([A-Z2-7]{8})*[A-Z2-7=]{8}.+")) //
														.validate(nameDoesNotContainLowercaseChars()) //
														.validate(hasSize(36).and(containsUuid()).and(referencedDirectoryExists)) //
														.validate(nameIsDecryptable) //
														.reportAs(aConflict()), //
												file().that(hasName("([A-Z2-7]{8})*[A-Z2-7=]{8}.+")) //
														.reportAs(emptyEncryptedFileIfEmpty) //
														.validate(nameDoesNotContainLowercaseChars()) //
														.validate(hasMinSize(88).and(isAuthentic(cryptor, checkContentIntegrity))) //
														.validate(nameIsDecryptable) //
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
												.validate(hasCorrespondingDFile.and(containsValidName())), //
										file().that(hasName("[A-Z2-7]{32}.+\\.lng")) //
												.validate(nameDoesNotContainLowercaseChars()) //
												.validate(hasCorrespondingDFile.and(containsValidName())) //
												.reportAs(aConflict())))), //
				file().that(hasName("masterkey.cryptomator")).validate(nameDoesNotContainUppercaseChars()), // do not validate contents because this already happened when creating the Cryptor
				file().that(hasName("masterkey.cryptomator.bkup")).validate(isMasterkeyBackupFile()));
	}

}
