package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;

class FileContentMismatchProblem implements Problem {

	private final Sensitive<Path> file;
	private final String expected;
	private final String actual;

	public FileContentMismatchProblem(Sensitive<Path> file, String expected, String actual) {
		this.file = file;
		this.expected = expected;
		this.actual = actual;
	}

	@Override
	public String toString() {
		return format("ContentMismatch file: %s expected: %s actual: %s", file, expected, actual);
	}

	@Override
	public Severity severity() {
		return Severity.ERROR;
	}

}
