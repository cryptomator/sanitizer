package org.cryptomator.sanitizer.integrity.problems;

import java.nio.file.Path;
import java.util.Optional;

import static java.lang.String.format;

public class NameNormalizationProblem implements Problem {

	private final Sensitive<Path> path;
	private final EncryptedNodeInfo encryptedNodeInfo;

	public NameNormalizationProblem(Sensitive<Path> path, EncryptedNodeInfo encryptedNodeInfo) {
		this.path = path;
		this.encryptedNodeInfo = encryptedNodeInfo;
	}

	@Override
	public String name() {
		return "NameNormalization";
	}

	@Override
	public String toString() {
		return format("NameNormalizationProblem file: %s", path);
	}

	@Override
	public Optional<Solution> solution() {
		return Optional.of(new NameNormalizationProblemSolution(encryptedNodeInfo));
	}

	@Override
	public Severity severity() {
		return Severity.ERROR;
	}

	public static class EncryptedNodeInfo {

		private final Path filePath;
		private final String directoryId;
		private final Optional<Path> mFile;

		public EncryptedNodeInfo(Path filePath, String directoryId, Optional<Path> mFile) {
			this.filePath = filePath;
			this.directoryId = directoryId;
			this.mFile = mFile;
		}

		public Path getFilePath() {
			return filePath;
		}

		public String getDirectoryId() {
			return directoryId;
		}

		public Optional<Path> getMFile() {
			return mFile;
		}
	}

}
