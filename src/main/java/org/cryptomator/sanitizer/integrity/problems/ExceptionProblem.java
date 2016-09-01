package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

class ExceptionProblem implements Problem {

	private final Sensitive<Exception> exception;

	public ExceptionProblem(Sensitive<Exception> e) {
		this.exception = e;
	}

	@Override
	public String toString() {
		return format("Exception %s", exception.toString().replace("\n", "\n\t"));
	}

	@Override
	public Severity severity() {
		return Severity.FATAL;
	}

}
