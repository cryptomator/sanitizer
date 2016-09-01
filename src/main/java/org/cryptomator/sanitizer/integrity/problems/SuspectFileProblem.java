package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;

class SuspectFileProblem implements Problem {

	private final Sensitive<Path> path;

	public SuspectFileProblem(Sensitive<Path> path) {
		this.path = path;
	}

	@Override
	public String toString() {
		return format("SuspectFile %s", path);
	}

	@Override
	public Severity severity() {
		return Severity.WARN;
	}

}
