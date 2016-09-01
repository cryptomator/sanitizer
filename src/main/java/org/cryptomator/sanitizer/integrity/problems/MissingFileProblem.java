package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;

class MissingFileProblem implements Problem {

	private final Severity severity;
	private final Sensitive<Path> path;

	public MissingFileProblem(Sensitive<Path> path, Severity severity) {
		this.path = path;
		this.severity = severity;
	}

	@Override
	public Severity severity() {
		return severity;
	}

	@Override
	public String toString() {
		return format("MissingFile %s", path);
	}

}
