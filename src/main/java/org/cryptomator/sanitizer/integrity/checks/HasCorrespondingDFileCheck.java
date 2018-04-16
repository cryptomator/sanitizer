package org.cryptomator.sanitizer.integrity.checks;

import org.cryptomator.sanitizer.integrity.problems.Problems;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.nio.file.Files.walk;
import static org.cryptomator.sanitizer.utils.NameUtil.decryptablePartOfName;

public class HasCorrespondingDFileCheck implements Check {

	private static final Pattern LNG_FILE = Pattern.compile("[A-Z2-7]{32}\\.lng");

	private final Path pathToVault;
	private final Map<String, Path> dFileNamesToPaths = new HashMap<>();
	private boolean dFilesCollected;

	public HasCorrespondingDFileCheck(Path pathToVault) {
		this.pathToVault = pathToVault;
	}

	@Override
	public void checkThrowingExceptions(Problems problems, Path path) throws IOException {
		collectDFiles();
		String fileName = path.getFileName().toString();
		if (!dFileNamesToPaths.containsKey(fileName)) {
			problems.reportOrphanMFile(path);
		}
	}

	public Optional<Path> pathOfDFile(Path mFileInMDir) {
		return pathOfDFile(mFileInMDir.getFileName().toString());
	}

	public Optional<Path> pathOfDFile(String mFileName) {
		String name = decryptablePartOfName(mFileName).orElse("") + ".lng";
		return Optional.ofNullable(dFileNamesToPaths.get(name));
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
					dFileNamesToPaths.put(fileName, file);
				}
			});
		}
	}

}
