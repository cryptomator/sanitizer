package org.cryptomator.sanitizer;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.Files.newBufferedWriter;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.WRITE;
import static java.util.Collections.sort;
import static java.util.stream.Collectors.toList;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UncheckedIOException;
import java.nio.CharBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.cryptomator.sanitizer.integrity.AbortCheckException;
import org.cryptomator.sanitizer.integrity.IntegrityCheck;
import org.cryptomator.sanitizer.integrity.problems.Problem;
import org.cryptomator.sanitizer.integrity.problems.Severity;
import org.cryptomator.sanitizer.integrity.problems.SolutionContext;

public class Sanitizer {

	public static void main(String[] stringArgs) {
		Args.parse(stringArgs).ifPresent(Sanitizer::main);
	}

	public static void main(Args args) {
		System.out.println("# Cryptomator vault sanitizer v" + Version.get() + " #");
		System.out.println();
		IntegrityCheck integrityCheck = new IntegrityCheck();
		CharBuffer passphrase = null;
		try {
			passphrase = args.passphrase();
			System.out.println("Checking the vault may take some time. Be patient...");
			System.out.println();
			Set<Problem> problems = integrityCheck.check(args.vaultLocation(), passphrase);
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

	private static void writeResultsToConsole(Args args, Set<Problem> problems) {
		System.out.println("Found " + problems.size() + " problem(s):");
		for (Severity severity : Severity.values()) {
			System.out.println("* " + problems.stream().filter(problem -> problem.severity() == severity).count() + " " + severity);
		}
		System.out.println();
		System.out.println("See " + args.outputFile() + " for details.");
	}

	private static void writeProblemsToOutput(Args args, Set<Problem> problems) {
		try (PrintWriter writer = new PrintWriter(newBufferedWriter(args.outputFile(), UTF_8, CREATE_NEW, WRITE))) {
			writer.println(problems.size() + " problem(s) found.");
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

	private static void clear(CharBuffer passphrase) {
		if (passphrase == null)
			return;
		passphrase.clear();
		while (passphrase.hasRemaining()) {
			passphrase.put('\0');
		}
	}

}