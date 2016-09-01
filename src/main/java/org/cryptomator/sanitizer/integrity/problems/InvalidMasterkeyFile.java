package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;

public class InvalidMasterkeyFile implements Problem {

	private final Sensitive<Path> path;
	private final Severity severity;

	public InvalidMasterkeyFile(Sensitive<Path> path, Severity severity) {
		this.path = path;
		this.severity = severity;
	}

	@Override
	public Severity severity() {
		return severity;
	}

	@Override
	public String toString() {
		return format("InvalidMasterkeyFile %s", path);
	}

}
