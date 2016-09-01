package org.cryptomator.sanitizer.integrity.checks;

import java.nio.file.Path;

import org.cryptomator.sanitizer.integrity.problems.Problems;

public interface FilteredCheck extends Check {

	default void check(Problems problems, Path path) {
		if (!matches(path))
			return;
		try {
			checkThrowingExceptions(problems, path);
		} catch (Exception e) {
			problems.reportException(e);
		}
	}

	default boolean required() {
		return false;
	}

	boolean matches(Path path);

}
