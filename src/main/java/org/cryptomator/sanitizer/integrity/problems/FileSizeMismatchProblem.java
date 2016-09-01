package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;

class FileSizeMismatchProblem implements Problem {

	private final Sensitive<Path> path;
	private final String expectedSize;
	private final long actualSize;

	public FileSizeMismatchProblem(Sensitive<Path> path, String expectedSize, long actualSize) {
		this.path = path;
		this.expectedSize = expectedSize;
		this.actualSize = actualSize;
	}

	@Override
	public String toString() {
		return format("SizeMismatch %s expected: %s actual: %d", path, expectedSize, actualSize);
	}

	@Override
	public Severity severity() {
		return Severity.ERROR;
	}

}
