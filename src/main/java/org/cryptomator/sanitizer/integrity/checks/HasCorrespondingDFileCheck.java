package org.cryptomator.sanitizer.integrity.checks;

import static java.nio.file.Files.walk;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.cryptomator.sanitizer.integrity.problems.Problems;

class HasCorrespondingDFileCheck implements Check {

	private static final Pattern LNG_FILE = Pattern.compile("[A-Z2-7]{32}\\.lng");

	private final Path pathToVault;
	private final Set<String> dFiles = new HashSet<>();
	private boolean dFilesCollected;

	public HasCorrespondingDFileCheck(Path pathToVault) {
		this.pathToVault = pathToVault;
	}

	@Override
	public void checkThrowingExceptions(Problems problems, Path path) throws IOException {
		collectDFiles();
		String fileName = path.getFileName().toString();
		if (!dFiles.contains(fileName)) {
			problems.reportOrphanMFile(path);
		}
	}

	private void collectDFiles() throws IOException {
		if (dFilesCollected)
			return;
		dFilesCollected = true;
		Path dFolder = pathToVault.resolve("d");
		try (Stream<Path> files = walk(dFolder, 3)) {
			files.filter(Files::isRegularFile).forEach(file -> {
				String fileName = file.getFileName().toString();
				if (dFolder.relativize(file).getNameCount() == 3 && LNG_FILE.matcher(fileName).matches()) {
					dFiles.add(fileName);
				}
			});
		}
	}

}
