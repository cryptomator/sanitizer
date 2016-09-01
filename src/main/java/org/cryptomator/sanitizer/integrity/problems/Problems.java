package org.cryptomator.sanitizer.integrity.problems;

import static java.util.Collections.unmodifiableSet;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

public class Problems {

	private final Set<Problem> problems = new HashSet<>();

	private final Optional<Path> pathToVault;

	public Problems(Path pathToVault) {
		this.pathToVault = Optional.of(pathToVault);
	}

	public Problems() {
		this.pathToVault = Optional.empty();
	}

	public void report(Problem problem) {
		problems.add(problem);
	}

	public Set<Problem> asSet() {
		return unmodifiableSet(problems);
	}

	public void reportMissingMFile(Path file, Path mFile) {
		report(new MissingMFileProblem(senstive(file), senstive(mFile)));
	}

	public void reportOrphanMFile(Path mFile) {
		report(new OrphanMFileProblem(senstive(mFile)));
	}

	public void reportException(Exception e) {
		report(new ExceptionProblem(sensitive(e)));
	}

	public void reportSuspectFile(Path child) {
		report(new SuspectFileProblem(senstive(child)));
	}

	public void reportFileContentProblem(Path path, String expected, String actual) {
		report(new FileContentProblem(senstive(path), expected, actual));
	}

	public void reportSizeMismatch(Path path, String expectedSize, long actualSize) {
		report(new FileSizeMismatchProblem(senstive(path), expectedSize, actualSize));
	}

	public void reportFileWithMissingEqualsSign(Path path) {
		report(new FileWithMissingEqualsSignProblem(senstive(path)));
	}

	public void reportConflict(Path path) {
		report(new ConflictProblem(senstive(path)));
	}

	public void reportNameProblem(String pattern, Path path) {
		report(new NameProblem(pattern, senstive(path)));
	}

	public void reportLowercasedFile(Path path) {
		report(new LowercasedFileProblem(senstive(path)));
	}

	public void reportUppercasedFile(Path path) {
		report(new UppercasedFileProblem(senstive(path)));
	}

	public void reportMissingMasterkeyFile(Path path) {
		report(new MissingFileProblem(senstive(path), Severity.FATAL));
	}

	public void reportMissingFile(Path path) {
		report(new MissingFileProblem(senstive(path), Severity.ERROR));
	}

	public void reportMissingFile(Path dir, String name) {
		report(new MissingFileProblem(senstive(dir), name, Severity.ERROR));
	}

	public void reportMissingDirectory(Path path, boolean exists) {
		report(new MissingDirectoryProblem(senstive(path), exists));
	}

	public void reportOrphanDirectory(Path path) {
		report(new OrphanDirectoryProblem(senstive(path)));
	}

	public void reportInvalidMasterkeyBackupFile(Path path) {
		report(new InvalidMasterkeyFile(senstive(path), Severity.WARN));
	}

	public void reportInvalidMasterkeyFile(Path path) {
		report(new InvalidMasterkeyFile(senstive(path), Severity.FATAL));
	}

	public void reportRootDirectoryExists(Path path) {
		report(new RootDirectoryInfo(senstive(path)));
	}

	private Sensitive<Exception> sensitive(Exception e) {
		return new Sensitive<Exception>() {
			@Override
			public Exception get() {
				return e;
			}

			@Override
			public String toString() {
				StringWriter traceWriter = new StringWriter();
				e.printStackTrace(new PrintWriter(traceWriter));
				String trace = traceWriter.toString();
				return pathToVault //
						.map(pathToVault -> trace.replace(pathToVault.toString(), "<vault>")) //
						.orElse(trace);
			}
		};
	}

	private Sensitive<Path> senstive(Path path) {
		return new Sensitive<Path>() {
			@Override
			public Path get() {
				return path;
			}

			@Override
			public String toString() {
				return pathToVault //
						.map(pathToVault -> pathToVault.relativize(path).toString()) //
						.orElseGet(() -> path.toString());
			}
		};
	}

}