package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;

class EmptyEncryptedFileInfo implements Problem {

	private final Sensitive<Path> path;

	public EmptyEncryptedFileInfo(Sensitive<Path> path) {
		this.path = path;
	}

	@Override
	public Severity severity() {
		return Severity.INFO;
	}

	@Override
	public String toString() {
		return format("EmptyEncryptedFile %s", path);
	}

}
