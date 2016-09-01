package org.cryptomator.sanitizer.integrity.problems;

import java.io.PrintStream;
import java.nio.file.Path;

public interface SolutionContext {

	public static SolutionContext simulatePrintingTo(Path vaultLocation, PrintStream out) {
		return new PrintStreamSolutionContext(vaultLocation, out, true);
	}

	public static SolutionContext executePrintingTo(Path vaultLocation, PrintStream out) {
		return new PrintStreamSolutionContext(vaultLocation, out, false);
	}

	void start(String format, Object... args);

	void finish();

	void fail(String format, Object... args);

	void fail(Throwable reason);

	boolean dryRun();

	Path vaultLocation();

}
