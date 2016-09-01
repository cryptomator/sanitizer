package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;

class MissingDirectoryProblem implements Problem {

	private final Sensitive<Path> directory;
	private final boolean exists;

	public MissingDirectoryProblem(Sensitive<Path> directory, boolean exists) {
		this.directory = directory;
		this.exists = exists;
	}

	@Override
	public Severity severity() {
		return Severity.WARN;
	}

	@Override
	public String toString() {
		return format("MissingDirectory path: %s notADirectoryButExists: %s", directory, exists);
	}

}
