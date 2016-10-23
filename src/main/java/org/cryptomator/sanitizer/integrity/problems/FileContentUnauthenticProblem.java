package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;

class FileContentUnauthenticProblem implements Problem {

	private final Sensitive<Path> file;
	private final long chunkNumber;

	public FileContentUnauthenticProblem(Sensitive<Path> file, long chunkNumber) {
		this.file = file;
		this.chunkNumber = chunkNumber;
	}

	@Override
	public String toString() {
		return format("Unauthentic file content at chunk %03d: %s", chunkNumber, file);
	}

	@Override
	public Severity severity() {
		return Severity.ERROR;
	}

}
