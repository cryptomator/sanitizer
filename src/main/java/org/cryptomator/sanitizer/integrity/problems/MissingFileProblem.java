package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;
import java.util.Optional;

class MissingFileProblem implements Problem {

	private final Severity severity;
	private final Optional<String> name;
	private final Sensitive<Path> path;

	public MissingFileProblem(Sensitive<Path> path, Severity severity) {
		this.path = path;
		this.name = Optional.empty();
		this.severity = severity;
	}

	public MissingFileProblem(Sensitive<Path> path, String name, Severity severity) {
		this.path = path;
		this.name = Optional.of(name);
		this.severity = severity;
	}

	@Override
	public Severity severity() {
		return severity;
	}

	@Override
	public String toString() {
		if (name.isPresent()) {
			return format("MissingFile name: %s inDirectory: %s", name.get(), path);
		} else {
			return format("MissingFile %s", path);
		}
	}

}
