package org.cryptomator.sanitizer.integrity.checks;

import static java.nio.file.Files.isDirectory;

import java.nio.file.Path;

public interface DirectoryCheck extends FilteredCheck {
	
	@Override
	default boolean matches(Path path) {
		return isDirectory(path) && dirMatches(path);
	}
	
	boolean dirMatches(Path path);
	
}
