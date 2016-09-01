package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;

public class NameProblem implements Problem {

	private final String pattern;
	private final Sensitive<Path> path;

	public NameProblem(String pattern, Sensitive<Path> path) {
		this.pattern = pattern;
		this.path = path;
	}

	@Override
	public String toString() {
		return format("NameMismatch file: %s expected: %s", path, pattern);
	}

	@Override
	public Severity severity() {
		return Severity.ERROR;
	}

}
