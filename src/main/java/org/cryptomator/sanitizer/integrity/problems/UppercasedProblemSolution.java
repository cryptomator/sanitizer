package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.Integer.MAX_VALUE;
import static java.lang.Math.random;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

class UppercasedProblemSolution implements Solution {

	private final Sensitive<Path> file;

	public UppercasedProblemSolution(Sensitive<Path> file) {
		this.file = file;
	}

	@Override
	public void execute(SolutionContext c) {
		try {
			c.start("Fix uppercase file %s", file);
			if (lowercaseFileExists()) {
				c.fail("%s exists", fileWithLowercaseName());
				return;
			}
			if (!c.dryRun()) {
				Path tempFile = tempFile();
				Files.move(file.get(), tempFile);
				Files.move(tempFile, fileWithLowercaseName());
			}
			c.finish();
		} catch (IOException e) {
			c.fail(e);
		}
	}

	private Path tempFile() {
		Path tempFile;
		do {
			String tempName = file.get().getFileName().toString() + "_" + (int) (random() * MAX_VALUE);
			Path parent = file.get().getParent();
			tempFile = parent.resolve(tempName);
		} while (Files.exists(tempFile));
		return tempFile;
	}

	private boolean lowercaseFileExists() throws IOException {
		String lowercaseName = lowercaseName();
		Path parent = file.get().getParent();
		try (Stream<Path> files = Files.list(parent)) {
			return files.anyMatch(file -> lowercaseName.equals(file.getFileName().toString()));
		}
	}

	private Path fileWithLowercaseName() {
		String lowercaseName = lowercaseName();
		Path parent = file.get().getParent();
		return parent.resolve(lowercaseName);
	}

	private String lowercaseName() {
		return file.get().getFileName().toString().toUpperCase();
	}

}
