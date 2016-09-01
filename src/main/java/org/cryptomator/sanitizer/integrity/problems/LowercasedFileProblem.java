package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;
import java.util.Optional;

class LowercasedFileProblem implements Problem {

	private final Sensitive<Path> path;

	public LowercasedFileProblem(Sensitive<Path> path) {
		this.path = path;
	}

	@Override
	public Severity severity() {
		return Severity.ERROR;
	}

	@Override
	public Optional<Solution> solution() {
		return Optional.of(new LowercasedFileProblemSolution(path));
	}

	@Override
	public String name() {
		return "LowercasedFile";
	}

	@Override
	public String toString() {
		return format("%s %s", name(), path);
	}

}
