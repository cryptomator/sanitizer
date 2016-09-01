package org.cryptomator.sanitizer.integrity.problems;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class OrphanMFileSolution implements Solution {

	private final Sensitive<Path> mFile;

	public OrphanMFileSolution(Sensitive<Path> mFile) {
		this.mFile = mFile;
	}

	@Override
	public void execute(SolutionContext c) {
		try {
			c.start("Remove orphan metadata file %s", mFile);
			if (!c.dryRun()) {
				Files.delete(mFile.get());
			}
			c.finish();
		} catch (IOException e) {
			c.fail(e);
		}
	}

}
