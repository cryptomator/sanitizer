package org.cryptomator.sanitizer;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.Files.isDirectory;
import static java.nio.file.Files.isRegularFile;
import static java.nio.file.Files.newBufferedWriter;
import static java.nio.file.Files.size;
import static java.nio.file.Files.walk;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.WRITE;
import static java.util.Collections.sort;
import static java.util.stream.Collectors.toList;
import static org.cryptomator.sanitizer.integrity.problems.Severity.INFO;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UncheckedIOException;
import java.nio.CharBuffer;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Stream;

import org.cryptomator.sanitizer.integrity.AbortCheckException;
import org.cryptomator.sanitizer.integrity.IntegrityCheck;
import org.cryptomator.sanitizer.integrity.problems.Problem;
import org.cryptomator.sanitizer.integrity.problems.Severity;
import org.cryptomator.sanitizer.integrity.problems.SolutionContext;

public class Sanitizer {

	private static final long PRINT_SIZE_TRESHOLD = 300;

	public static void main(String[] stringArgs) {
		System.out.println("# Cryptomator vault sanitizer v" + Version.get() + " #");
		System.out.println();
		Args.parse(stringArgs).ifPresent(Sanitizer::main);
	}

	public static void main(Args args) {
		IntegrityCheck integrityCheck = new IntegrityCheck();
		CharBuffer passphrase = null;
		try {
			passphrase = args.passphrase();
			System.out.println("Scanning vault structure may take some time. Be patient...");
			writeStructureToOutput(args, args.vaultLocation());
			System.out.println("Checking the vault may take some time. Be patient...");
			System.out.println();
			Set<Problem> problems = integrityCheck.check(args.vaultLocation(), passphrase, args.checkFileIntegrity());
			writeResultsToConsole(args, problems);
			writeProblemsToOutput(args, problems);
			List<Problem> problemsToSolve = problems.stream() //
					.filter(problem -> args.problemsToSolve().contains(problem.name())) //
					.collect(toList());
			if (!problemsToSolve.isEmpty()) {
				System.out.println();
				System.out.println("Solving problems. This may take some time. Be patient...");
				System.out.println();
				SolutionContext context = SolutionContext.executePrintingTo(args.vaultLocation(), System.out);
				problemsToSolve.forEach(problem -> problem.solution().ifPresent(solution -> solution.execute(context)));
			}
			System.out.println();
			System.out.println("Done.");
		} catch (AbortCheckException e) {
			System.err.print("Check failed: ");
			System.err.println(e.getMessage());
		} finally {
			clear(passphrase);
		}
	}

	private static void writeStructureToOutput(Args args, Path vaultLocation) {
		try (PrintWriter writer = new PrintWriter(newBufferedWriter(args.structureOutputFile(), UTF_8, CREATE_NEW, WRITE)); //
				Stream<Path> vaultContents = walk(vaultLocation)) {
			vaultContents.forEach(writePathToOutput(args, writer));
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
		System.out.println("Wrote structure to " + args.structureOutputFile() + ".");
		System.out.println();
	}

	private static Consumer<Path> writePathToOutput(Args args, PrintWriter writer) {
		return path -> {
			try {
				Path relativePath = args.vaultLocation().relativize(path);
				if (isDirectory(path)) {
					writer.println(format("d %s", relativePath));
				} else if (isRegularFile(path)) {
					writer.println(format("f %s %s", relativePath, applySizeTrehsold(size(path))));
				} else {
					writer.println(format("? %s", relativePath));
				}
			} catch (IOException e) {
				throw new UncheckedIOException(e);
			}
		};
	}

	private static String applySizeTrehsold(long size) {
		if (size < PRINT_SIZE_TRESHOLD) {
			return Long.toString(size);
		} else {
			return ">" + PRINT_SIZE_TRESHOLD;
		}
	}

	private static void writeResultsToConsole(Args args, Set<Problem> problems) {
		System.out.println("Found " + countProblems(problems) + " problem(s):");
		for (Severity severity : Severity.values()) {
			System.out.println("* " + problems.stream().filter(problem -> problem.severity() == severity).count() + " " + severity);
		}
		System.out.println();
		System.out.println("See " + args.checkOutputFile() + " for details.");
	}

	private static void writeProblemsToOutput(Args args, Set<Problem> problems) {
		try (PrintWriter writer = new PrintWriter(newBufferedWriter(args.checkOutputFile(), UTF_8, CREATE_NEW, WRITE))) {
			writer.println(countProblems(problems) + " problem(s) found.");
			if (problems.isEmpty()) {
				return;
			}
			List<Problem> sortedProblems = new ArrayList<>(problems);
			sort(sortedProblems, (p1, p2) -> {
				int bySeverity = p1.severity().ordinal() - p2.severity().ordinal();
				if (bySeverity == 0) {
					return p1.toString().compareTo(p2.toString());
				} else {
					return bySeverity;
				}
			});
			sortedProblems.forEach(problem -> {
				writer.print(format("%-5s", problem.severity()));
				writer.print(' ');
				writer.println(problem);
			});
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	private static long countProblems(Set<Problem> problems) {
		return problems.stream().filter(problem -> problem.severity() != INFO).count();
	}

	private static void clear(CharBuffer passphrase) {
		if (passphrase == null)
			return;
		passphrase.clear();
		while (passphrase.hasRemaining()) {
			passphrase.put('\0');
		}
	}

}