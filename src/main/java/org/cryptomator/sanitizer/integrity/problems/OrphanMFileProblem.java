package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;
import java.util.Optional;

class OrphanMFileProblem implements Problem {

	private final Sensitive<Path> mFile;

	public OrphanMFileProblem(Sensitive<Path> mFile) {
		this.mFile = mFile;
	}

	public Sensitive<Path> getMFile() {
		return mFile;
	}

	@Override
	public String toString() {
		return format("%s %s", name(), mFile);
	}

	@Override
	public Severity severity() {
		return Severity.INFO;
	}

	@Override
	public String name() {
		return "OrphanMFile";
	}

	@Override
	public Optional<Solution> solution() {
		return Optional.of(new OrphanMFileSolution(mFile));
	}

}
