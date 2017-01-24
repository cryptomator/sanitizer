package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;
import java.util.Optional;

class FileSizeOfZeroInHeaderProblem implements Problem {

	private final Sensitive<Path> path;

	public FileSizeOfZeroInHeaderProblem(Sensitive<Path> path) {
		this.path = path;
	}

	@Override
	public String name() {
		return "FileSizeOfZeroInHeader";
	}

	@Override
	public String toString() {
		return format("FileSizeOfZeroInHeader %s", path);
	}

	@Override
	public Severity severity() {
		return Severity.ERROR;
	}

	@Override
	public Optional<Solution> solution() {
		return Optional.of(new FileSizeOfZeroInHeaderProblemSolution(path));
	}

}
