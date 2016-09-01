package org.cryptomator.sanitizer.integrity.checks;

import static java.nio.file.Files.exists;

import java.io.IOException;
import java.nio.file.Path;

import org.cryptomator.sanitizer.integrity.problems.Problems;

public class HasCorrespondingMFileCheck implements Check {

	private final Path mDirectory;
	
	private Check mFileCheck = (problems,path) -> {};
	
	HasCorrespondingMFileCheck(Path pathToVault) {
		this.mDirectory = pathToVault.resolve("m");
	}
	
	public HasCorrespondingMFileCheck that(Check check) {
		mFileCheck = check;
		return this;
	}

	@Override
	public void checkThrowingExceptions(Problems problems, Path path) throws IOException {
		String fileName = path.getFileName().toString();
		String firstTwoChars = fileName.substring(0, 2);
		String nextTwoChars = fileName.substring(2, 4);
		Path mFile = mDirectory.resolve(firstTwoChars).resolve(nextTwoChars).resolve(fileName);
		if (exists(mFile)) {
			mFileCheck.check(problems, mFile);
		} else {
			problems.reportMissingMFile(path, mFile);
		}
		
	}

}
