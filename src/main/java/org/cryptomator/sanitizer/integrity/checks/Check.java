package org.cryptomator.sanitizer.integrity.checks;

import java.io.IOException;
import java.nio.file.Path;
import java.util.function.Predicate;

import org.cryptomator.sanitizer.integrity.problems.Problems;

public interface Check extends Predicate<Path> {

	default Check and(Check other) {
		return (problems,path) -> {
			if (test(path)) {
				other.check(problems, path);
			} else {
				check(problems, path);
			}
		};
	}
	
	@Override
	default boolean test(Path path) {
		Problems problems = new Problems();
		check(problems, path);
		return problems.asSet().isEmpty();
	}

	default void check(Problems problems, Path path) {
		try {
			checkThrowingExceptions(problems, path);
		} catch (Exception e) {
			problems.reportException(e);
		}
	}
	
	void checkThrowingExceptions(Problems problems, Path path) throws IOException;
	
}
