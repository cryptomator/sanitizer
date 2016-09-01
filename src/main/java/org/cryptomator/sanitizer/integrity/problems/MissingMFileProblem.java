package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.nio.file.Path;

class MissingMFileProblem implements Problem {

	private final Sensitive<Path> file;
	private final Sensitive<Path> mFile;

	public MissingMFileProblem(Sensitive<Path> file, Sensitive<Path> mFile) {
		this.file = file;
		this.mFile = mFile;
	}

	public Sensitive<Path> getFile() {
		return file;
	}

	public Sensitive<Path> getMFile() {
		return mFile;
	}

	@Override
	public String toString() {
		return format("MissingMFile file: %s mFile: %s", file, mFile);
	}

	@Override
	public Severity severity() {
		return Severity.ERROR;
	}

}
