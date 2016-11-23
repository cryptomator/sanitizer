package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;

class FileSizeInHeaderProblem implements Problem {

	private final Sensitive<Path> path;

	public FileSizeInHeaderProblem(Sensitive<Path> path) {
		this.path = path;
	}

	@Override
	public String toString() {
		return format("FileSizeInHeader %s", path);
	}

	@Override
	public Severity severity() {
		return Severity.WARN;
	}

}
