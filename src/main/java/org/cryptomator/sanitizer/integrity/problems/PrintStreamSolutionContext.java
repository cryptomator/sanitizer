package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;

import java.io.PrintStream;
import java.nio.file.Path;

import org.cryptomator.cryptolib.api.Cryptor;

class PrintStreamSolutionContext implements SolutionContext {

	private final Path vaultLocation;
	private final PrintStream out;
	private final boolean dryRun;
	private final Cryptor cryptor;

	public PrintStreamSolutionContext(Path vaultLocation, Cryptor cryptor, PrintStream out, boolean dryRun) {
		this.vaultLocation = vaultLocation;
		this.cryptor = cryptor;
		this.out = out;
		this.dryRun = dryRun;
	}

	@Override
	public void start(String format, Object... args) {
		out.print(format(format + "... ", args));
	}

	@Override
	public void finish() {
		out.println("[OK]");
	}

	@Override
	public void fail(String format, Object... args) {
		out.println("[FAILED]");
		out.println(format(format, args));
	}

	@Override
	public void fail(Throwable reason) {
		out.println("[FAILED]");
		reason.printStackTrace(out);
	}

	@Override
	public boolean dryRun() {
		return dryRun;
	}

	@Override
	public Path vaultLocation() {
		return vaultLocation;
	}

	@Override
	public Cryptor cryptor() {
		return cryptor;
	}

}
