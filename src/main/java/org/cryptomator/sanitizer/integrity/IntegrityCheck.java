package org.cryptomator.sanitizer.integrity;

import static java.lang.String.format;
import static java.nio.file.Files.isRegularFile;
import static java.nio.file.Files.readAllBytes;
import static org.cryptomator.sanitizer.integrity.checks.Checks.aConflict;
import static org.cryptomator.sanitizer.integrity.checks.Checks.aFileWithMissingEqualsSign;
import static org.cryptomator.sanitizer.integrity.checks.Checks.containsUuid;
import static org.cryptomator.sanitizer.integrity.checks.Checks.containsValidDirectoryFileName;
import static org.cryptomator.sanitizer.integrity.checks.Checks.containsValidFileName;
import static org.cryptomator.sanitizer.integrity.checks.Checks.containsValidName;
import static org.cryptomator.sanitizer.integrity.checks.Checks.dir;
import static org.cryptomator.sanitizer.integrity.checks.Checks.file;
import static org.cryptomator.sanitizer.integrity.checks.Checks.hasCorrespondingDFileIn;
import static org.cryptomator.sanitizer.integrity.checks.Checks.hasCorrespondingDirectoryFile;
import static org.cryptomator.sanitizer.integrity.checks.Checks.hasCorrespondingMFileIn;
import static org.cryptomator.sanitizer.integrity.checks.Checks.hasMinSize;
import static org.cryptomator.sanitizer.integrity.checks.Checks.hasName;
import static org.cryptomator.sanitizer.integrity.checks.Checks.hasSize;
import static org.cryptomator.sanitizer.integrity.checks.Checks.isMasterkeyBackupFile;
import static org.cryptomator.sanitizer.integrity.checks.Checks.nameDoesNotContainLowercaseChars;
import static org.cryptomator.sanitizer.integrity.checks.Checks.nameDoesNotContainUppercaseChars;
import static org.cryptomator.sanitizer.integrity.checks.Checks.nameIsDecryptable;
import static org.cryptomator.sanitizer.integrity.checks.Checks.referencedDirectoryExists;
import static org.cryptomator.sanitizer.integrity.checks.Checks.rootDirectoryIfMachting;
import static org.cryptomator.sanitizer.integrity.checks.Checks.startsWithAuthenticHeader;

import java.io.IOException;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Optional;
import java.util.Set;

import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.cryptolib.api.KeyFile;
import org.cryptomator.sanitizer.integrity.checks.Check;
import org.cryptomator.sanitizer.integrity.checks.HasCorrespondingDirectoryFileCheck;
import org.cryptomator.sanitizer.integrity.problems.Problem;
import org.cryptomator.sanitizer.integrity.problems.Problems;

public class IntegrityCheck {

	private static final int VAULT_VERSION = 4;

	private final CryptorProvider cryptorProvider;

	public IntegrityCheck() {
		try {
			this.cryptorProvider = Cryptors.version1(SecureRandom.getInstanceStrong());
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Java platform is required to support a strong SecureRandom.", e);
		}
	}

	public Set<Problem> check(Path path, CharSequence passphrase) throws AbortCheckException {
		Problems problems = new Problems(path);
		try {
			createCryptor(problems, path, passphrase).ifPresent(cryptor -> {
				try {
					vaultFormatChecks(cryptor, path).check(problems, path);
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

	private Optional<Cryptor> createCryptor(Problems problems, Path path, CharSequence passphrase) throws IOException, AbortCheckException {
		Path masterkeyFile = path.resolve("masterkey.cryptomator");
		try {
			if (!isRegularFile(masterkeyFile)) {
				problems.reportMissingMasterkeyFile(masterkeyFile);
				return Optional.empty();
			}
			KeyFile keyFile = KeyFile.parse(readAllBytes(masterkeyFile));
			if (keyFile.getVersion() != VAULT_VERSION) {
				throw new AbortCheckException(format("Vault version mismatch. Exepcted: %d Actual: %d", VAULT_VERSION, keyFile.getVersion()));
			}
			return Optional.of(cryptorProvider.createFromKeyFile(keyFile, passphrase, keyFile.getVersion()));
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
		return Optional.empty();
	}

	private Check vaultFormatChecks(Cryptor cryptor, Path pathToVault) {
		Check referencedDirectoryExists = referencedDirectoryExists(cryptor, pathToVault);
		HasCorrespondingDirectoryFileCheck hasCorrespondingDirectoryFileCheck = hasCorrespondingDirectoryFile(cryptor, pathToVault);
		Check nameIsDecryptable = nameIsDecryptable(cryptor, hasCorrespondingDirectoryFileCheck);
		Check hasCorrespondingDFile = hasCorrespondingDFileIn(pathToVault);
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
														.validate(nameDoesNotContainLowercaseChars()) //
														.validate(hasMinSize(88).and(startsWithAuthenticHeader(cryptor))) //
														.validate(nameIsDecryptable), //
												file().that(hasName("[A-Z2-7]{32}\\.lng").and(hasCorrespondingMFileIn(pathToVault).that(containsValidFileName()))) //
														.validate(nameDoesNotContainLowercaseChars()) //
														.validate(hasMinSize(88).and(startsWithAuthenticHeader(cryptor))), //
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
														.validate(nameDoesNotContainLowercaseChars()) //
														.validate(hasMinSize(88).and(startsWithAuthenticHeader(cryptor))) //
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
				file().that(hasName("masterkey.cryptomator")).validate(nameDoesNotContainUppercaseChars()), // do not validate contents because this already happend when creating the Cryptor
				file().that(hasName("masterkey.cryptomator.bkup")).validate(isMasterkeyBackupFile()));
	}

}
