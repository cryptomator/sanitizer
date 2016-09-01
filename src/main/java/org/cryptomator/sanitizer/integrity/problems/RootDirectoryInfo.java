package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;

public class RootDirectoryInfo implements Problem {

	private final Sensitive<Path> path;

	public RootDirectoryInfo(Sensitive<Path> path) {
		this.path = path;
	}

	@Override
	public Severity severity() {
		return Severity.INFO;
	}

	@Override
	public String toString() {
		return format("RootExists %s", path);
	}

}
