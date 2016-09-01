package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;

class OrphanDirectoryProblem implements Problem {

	private final Sensitive<Path> path;

	public OrphanDirectoryProblem(Sensitive<Path> path) {
		this.path = path;
	}

	@Override
	public Severity severity() {
		return Severity.WARN;
	}

	@Override
	public String toString() {
		return format("OrphanDirectory %s", path);
	}

}
