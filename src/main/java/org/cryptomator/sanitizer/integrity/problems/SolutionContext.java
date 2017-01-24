package org.cryptomator.sanitizer.integrity.problems;

import java.io.PrintStream;
import java.nio.file.Path;

import org.cryptomator.cryptolib.api.Cryptor;

public interface SolutionContext {

	public static SolutionContext simulatePrintingTo(Path vaultLocation, Cryptor cryptor, PrintStream out) {
		return new PrintStreamSolutionContext(vaultLocation, cryptor, out, true);
	}

	public static SolutionContext executePrintingTo(Path vaultLocation, Cryptor cryptor, PrintStream out) {
		return new PrintStreamSolutionContext(vaultLocation, cryptor, out, false);
	}

	void start(String format, Object... args);

	void finish();

	void fail(String format, Object... args);

	void fail(Throwable reason);

	boolean dryRun();

	Path vaultLocation();

	Cryptor cryptor();

}
