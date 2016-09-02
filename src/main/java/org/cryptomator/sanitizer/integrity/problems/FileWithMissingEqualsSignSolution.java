package org.cryptomator.sanitizer.integrity.problems;

import static org.cryptomator.sanitizer.utils.NameUtil.numMissing;
import static org.cryptomator.sanitizer.utils.StringUtils.repeat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

class FileWithMissingEqualsSignSolution implements Solution {

	private final Sensitive<Path> file;

	public FileWithMissingEqualsSignSolution(Sensitive<Path> file) {
		this.file = file;
	}

	@Override
	public void execute(SolutionContext c) {
		try {
			c.start("Fix missing equals sign for %s", file);
			Path fileWithFixedName = fileWithFixedName(file.get());
			if (Files.exists(fileWithFixedName)) {
				c.fail("%s exists", fileWithFixedName);
				return;
			}
			if (!c.dryRun()) {
				Files.move(file.get(), fileWithFixedName);
			}
			c.finish();
		} catch (IOException e) {
			c.fail(e);
		}
	}

	private Path fileWithFixedName(Path absoluteFile) {
		String name = absoluteFile.getFileName().toString();
		String fixedName = name + repeat('=', numMissing(name));
		return absoluteFile.getParent().resolve(fixedName);
	}

}
