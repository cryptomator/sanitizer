package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;
import java.util.Optional;

class FileSizeInHeaderProblem implements Problem {

	private final Sensitive<Path> path;
	private final long filesize;

	public FileSizeInHeaderProblem(Sensitive<Path> path, long filesize) {
		if (filesize == 0L) {
			throw new IllegalArgumentException("Use FileSizeOfZeroInHeaderProblem");
		}
		this.path = path;
		this.filesize = filesize;
	}

	@Override
	public String name() {
		return "FileSizeInHeader";
	}

	@Override
	public String toString() {
		return format("FileSizeInHeader %s %d", path, filesize);
	}

	@Override
	public Severity severity() {
		return Severity.ERROR;
	}

	@Override
	public Optional<Solution> solution() {
		return Optional.of(new FileSizeInHeaderProblemSolution(path));
	}

}
