package org.cryptomator.sanitizer.integrity.problems;

import org.cryptomator.sanitizer.integrity.problems.NameNormalizationProblem.EncryptedNodeInfo;
import org.cryptomator.sanitizer.utils.NameUtil;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.Normalizer;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.Files.readAllBytes;
import static org.cryptomator.sanitizer.utils.NameUtil.decryptablePartOfName;

class NameNormalizationProblemSolution implements Solution {

	private final EncryptedNodeInfo encryptedNodeInfo;

	public NameNormalizationProblemSolution(EncryptedNodeInfo encryptedNodeInfo) {
		this.encryptedNodeInfo = encryptedNodeInfo;
	}

	@Override
	public void execute(SolutionContext c) {
		try {
			c.start("Fix non NFC file %s", encryptedNodeInfo.getFilePath());
			int counter = 0;
			String decryptablePartOfName;
			if (encryptedNodeInfo.getMFile().isPresent()) {
				decryptablePartOfName = decryptablePartOfName(new String(readAllBytes(encryptedNodeInfo.getMFile().get()), UTF_8)).get();
			} else {
				decryptablePartOfName = decryptablePartOfName(encryptedNodeInfo.getFilePath().getFileName().toString()).get();
			}
			String cleartextName = c.cryptor().fileNameCryptor().decryptFilename(decryptablePartOfName, encryptedNodeInfo.getDirectoryId().getBytes(UTF_8));
			cleartextName = Normalizer.normalize(cleartextName, Normalizer.Form.NFC);
			Path correctFile;
			Optional<Path> correctMFile;
			String correctName;
			do {
				String correctCleartextName;
				if (counter == 0) {
					correctCleartextName = cleartextName;
				} else {
					correctCleartextName = cleartextName + " (" + counter + ')';
				}
				correctName = c.cryptor().fileNameCryptor().encryptFilename(correctCleartextName, encryptedNodeInfo.getDirectoryId().getBytes(UTF_8));
				if (encryptedNodeInfo.getMFile().isPresent()) {
					String mFileHash = NameUtil.mFileHash(correctName);
					correctFile = encryptedNodeInfo.getFilePath().getParent().resolve(mFileHash + ".lng");
					correctMFile = Optional.of(c.vaultLocation()
							.resolve("m")
							.resolve(mFileHash.substring(0, 2))
							.resolve(mFileHash.substring(2, 4))
							.resolve(mFileHash + ".lng"));
				} else {
					correctFile = encryptedNodeInfo.getFilePath().getParent().resolve(correctName);
					correctMFile = Optional.empty();
				}
			} while (Files.exists(correctFile));

			if (!c.dryRun()) {
				Files.move(encryptedNodeInfo.getFilePath(), correctFile);
				if (correctMFile.isPresent()) {
					Files.createDirectories(correctMFile.get().getParent());
					Files.write(correctMFile.get(), correctName.getBytes(UTF_8));
				}
			}
			c.finish();
		} catch (IOException e) {
			c.fail(e);
		}
	}

}
