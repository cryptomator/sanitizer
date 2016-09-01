package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.Integer.MAX_VALUE;
import static java.lang.Math.random;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

class LowercasedFileProblemSolution implements Solution {

	private final Sensitive<Path> file;

	public LowercasedFileProblemSolution(Sensitive<Path> file) {
		this.file = file;
	}

	@Override
	public void execute(SolutionContext c) {
		try {
			c.start("Fix lowercase file %s", file);
			if (uppercaseFileExists()) {
				c.fail("%s exists", fileWithUppercaseName());
				return;
			}
			if (!c.dryRun()) {
				Path tempFile = tempFile();
				Files.move(file.get(), tempFile);
				Files.move(tempFile, fileWithUppercaseName());
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

	private boolean uppercaseFileExists() throws IOException {
		String uppercaseName = uppercaseName();
		Path parent = file.get().getParent();
		try (Stream<Path> files = Files.list(parent)) {
			return files.anyMatch(file -> uppercaseName.equals(file.getFileName().toString()));
		}
	}

	private Path fileWithUppercaseName() {
		String uppercaseName = uppercaseName();
		Path parent = file.get().getParent();
		return parent.resolve(uppercaseName);
	}

	private String uppercaseName() {
		return file.get().getFileName().toString().toUpperCase();
	}

}
