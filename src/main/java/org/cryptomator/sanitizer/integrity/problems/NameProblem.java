package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;

public class NameProblem implements Problem {

	private final String expected;
	private final Sensitive<Path> path;

	public NameProblem(String expected, Sensitive<Path> path) {
		this.expected = expected;
		this.path = path;
	}

	@Override
	public String toString() {
		return format("NameProblem file: %s expected: %s", path, expected);
	}

	@Override
	public Severity severity() {
		return Severity.ERROR;
	}

}
