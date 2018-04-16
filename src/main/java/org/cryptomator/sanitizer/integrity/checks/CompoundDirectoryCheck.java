package org.cryptomator.sanitizer.integrity.checks;

import org.cryptomator.sanitizer.integrity.problems.Problems;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Stream;

import static java.util.Arrays.asList;
import static java.util.stream.Collectors.toSet;

public class CompoundDirectoryCheck implements DirectoryCheck {

	private static final Set<String> ALLOWED_ADDITIONAL_FILENAMES = new HashSet<>(asList("desktop.ini"));

	private final String name;
	private final boolean required;
	private List<Check> validations = new ArrayList<>();
	private List<Check> matchesChecks = new ArrayList<>();

	CompoundDirectoryCheck() {
		this.name = "?";
		this.required = false;
	}

	CompoundDirectoryCheck(String name) {
		this.name = name;
		this.required = true;
	}

	@Override
	public boolean dirMatches(Path path) {
		return matchesChecks.stream().allMatch(check -> check.test(path));
	}

	@Override
	public void checkThrowingExceptions(Problems problems, Path path) throws IOException {
		validations.forEach(check -> check.check(problems, path));
	}

	public CompoundDirectoryCheck validate(Check check) {
		validations.add(check);
		return this;
	}

	public CompoundDirectoryCheck reportAs(Check check) {
		validations.add(check);
		return this;
	}

	public CompoundDirectoryCheck that(Check check) {
		matchesChecks.add(check);
		return this;
	}

	public CompoundDirectoryCheck containing(FilteredCheck... checksAsArray) {
		Collection<FilteredCheck> checks = asList(checksAsArray);
		this.validations.add((problems, dir) -> {
			Set<FilteredCheck> unusedRequiredChecks = checks.stream() //
					.filter(FilteredCheck::required).collect(toSet());
			try (Stream<Path> children = Files.list(dir)) {
				children.forEach(child -> {
					Optional<FilteredCheck> check = checks.stream() //
							.filter(c -> c.matches(child)).findFirst();
					if (check.isPresent()) {
						unusedRequiredChecks.remove(check.get());
						check.get().check(problems, child);
					} else {
						if (!isAllowed(child)) {
							problems.reportSuspectFile(child);
						}
					}
				});
			}
			unusedRequiredChecks.forEach(check -> {
				problems.reportMissingFile(dir, check.toString());
			});
		});
		return this;
	}

	@Override
	public String toString() {
		return name;
	}

	private boolean isAllowed(Path file) {
		String name = file.getFileName().toString();
		return name.startsWith(".") || ALLOWED_ADDITIONAL_FILENAMES.contains(name);
	}

	@Override
	public boolean required() {
		return required;
	}

}
