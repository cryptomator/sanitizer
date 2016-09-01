package org.cryptomator.sanitizer.integrity.problems;

import java.util.Optional;

public interface Problem {

	Severity severity();

	default Optional<Solution> solution() {
		return Optional.empty();
	}

	default String name() {
		return "notSolvable";
	}

}
