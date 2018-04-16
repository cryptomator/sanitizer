package org.cryptomator.sanitizer.integrity.checks;

import org.cryptomator.sanitizer.integrity.problems.Problems;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static java.nio.file.Files.isRegularFile;

public class CompoundFileCheck implements FileCheck {

	private final String name;
	private final boolean required;
	private List<Check> validations = new ArrayList<>();
	private List<Check> matchesChecks = new ArrayList<>();

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
