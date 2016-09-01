package org.cryptomator.sanitizer.integrity.checks;

import static java.nio.file.Files.isRegularFile;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

import org.cryptomator.sanitizer.integrity.problems.Problems;

public class CompoundFileCheck implements FileCheck {

	private Set<Check> validations = new HashSet<>();
	private Set<Check> matchesChecks = new HashSet<>();
	
	CompoundFileCheck() {}
	
	@Override
	public boolean fileMatches(Path path) {
		return isRegularFile(path) && matchesChecks.stream().allMatch(check -> check.test(path));
	}

	@Override
	public void checkThrowingExceptions(Problems problems, Path path) throws IOException {
		validations.forEach(check -> check.check(problems, path));
	}
	
	public CompoundFileCheck that(Check check) {
		matchesChecks.add(check);
		return this;
	}
	
	public CompoundFileCheck reportAs(Check check) {
		validations.add(check);
		return this;
	}
	
	public CompoundFileCheck validate(Check check) {
		validations.add(check);
		return this;
	}

}
