package org.cryptomator.sanitizer.integrity.checks;

import static org.cryptomator.sanitizer.utils.NameUtil.decryptablePartOfName;

import java.io.IOException;
import java.nio.file.Path;

import org.cryptomator.sanitizer.integrity.problems.Problems;

class NameDoesNotContainLowercaseCharsCheck implements Check {

	@Override
	public void checkThrowingExceptions(Problems problems, Path path) throws IOException {
		String filename = decryptablePartOfName(path.getFileName().toString()).orElse("");
		for (char c : filename.toCharArray()) {
			if (Character.isLowerCase(c)) {
				problems.reportLowercasedFile(path);
				return;
			}
		}
	}

}
