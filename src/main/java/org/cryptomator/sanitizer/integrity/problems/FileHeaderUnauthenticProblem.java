package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;

class FileHeaderUnauthenticProblem implements Problem {

	private final Sensitive<Path> file;

	public FileHeaderUnauthenticProblem(Sensitive<Path> file) {
		this.file = file;
	}

	@Override
	public String toString() {
		return format("Unauthentic file header: %s", file);
	}

	@Override
	public Severity severity() {
		return Severity.ERROR;
	}

}
