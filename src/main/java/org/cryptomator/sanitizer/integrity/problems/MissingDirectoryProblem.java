package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;

class MissingDirectoryProblem implements Problem {

	private final Sensitive<Path> directory;
	private final Sensitive<Path> dirfile;
	private final boolean exists;

	public MissingDirectoryProblem(Sensitive<Path> directory, Sensitive<Path> dirfile, boolean exists) {
		this.directory = directory;
		this.dirfile = dirfile;
		this.exists = exists;
	}

	@Override
	public Severity severity() {
		return Severity.WARN;
	}

	@Override
	public String toString() {
		return format("MissingDirectory path: %s dirfile: %s notADirectoryButExists: %s", directory, dirfile, exists);
	}

}
