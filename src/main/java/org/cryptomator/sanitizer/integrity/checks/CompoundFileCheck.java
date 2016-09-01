package org.cryptomator.sanitizer.integrity.checks;

import static java.nio.file.Files.isRegularFile;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

import org.cryptomator.sanitizer.integrity.problems.Problems;

public class CompoundFileCheck implements FileCheck {

	private final String name;
	private final boolean required;
	private Set<Check> validations = new HashSet<>();
	private Set<Check> matchesChecks = new HashSet<>();

	CompoundFileCheck() {
		this.name = "?";
		this.required = false;
	}

	CompoundFileCheck(String name) {
		this.name = name;
		this.required = true;
	}

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

	@Override
	public String toString() {
		return name;
	}

	@Override
	public boolean required() {
		return required;
	}

}
