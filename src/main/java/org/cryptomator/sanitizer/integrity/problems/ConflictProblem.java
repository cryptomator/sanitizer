package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;

class ConflictProblem implements Problem {

	private final Sensitive<Path> path;

	public ConflictProblem(Sensitive<Path> path) {
		this.path = path;
	}

	@Override
	public String toString() {
		return format("Conflict %s", path);
	}

	@Override
	public Severity severity() {
		return Severity.WARN;
	}

}
