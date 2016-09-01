package org.cryptomator.sanitizer.integrity.checks;

import static java.util.Arrays.asList;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import org.cryptomator.sanitizer.integrity.problems.Problems;

public class CompoundDirectoryCheck implements DirectoryCheck {

	private static final Set<String> ALLOWED_ADDITIONAL_FILENAMES = new HashSet<>(asList("desktop.ini"));

	private Set<Check> validations = new HashSet<>();
	private Set<Check> matchesChecks = new HashSet<>();

	CompoundDirectoryCheck() {
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
			try (Stream<Path> children = Files.list(dir)) {
				children.forEach(child -> {
					Optional<FilteredCheck> check = checks.stream() //
							.filter(c -> c.matches(child)).findFirst();
					if (check.isPresent()) {
						check.get().check(problems, child);
					} else {
						if (!isAllowed(child)) {
							problems.reportSuspectFile(child);
						}
					}
				});
			}
		});
		return this;
	}

	private boolean isAllowed(Path file) {
		String name = file.getFileName().toString();
		return name.startsWith(".") || ALLOWED_ADDITIONAL_FILENAMES.contains(name);
	}

}
