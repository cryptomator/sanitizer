package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;
import java.util.Optional;

class FileWithMissingEqualsSignProblem implements Problem {

	private final Sensitive<Path> file;

	public FileWithMissingEqualsSignProblem(Sensitive<Path> file) {
		this.file = file;
	}

	@Override
	public String toString() {
		return format("%s %s", name(), file);
	}

	@Override
	public String name() {
		return "MissingEqualsSign";
	}

	@Override
	public Severity severity() {
		return Severity.ERROR;
	}

	@Override
	public Optional<Solution> solution() {
		return Optional.of(new FileWithMissingEqualsSignSolution(file));
	}

}
