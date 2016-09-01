package org.cryptomator.sanitizer.integrity.checks;

import static java.nio.file.Files.isRegularFile;

import java.nio.file.Path;

interface FileCheck extends FilteredCheck {
	
	@Override
	default boolean matches(Path path) {
		return isRegularFile(path) && fileMatches(path);
	}
	
	boolean fileMatches(Path path);
	
}
