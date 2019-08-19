package org.cryptomator.sanitizer.commands;

import java.io.IOException;

import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.sanitizer.Passphrase;
import org.cryptomator.sanitizer.integrity.AbortCheckException;
import org.cryptomator.sanitizer.restorer.PathEncryptor;

class EncryptPathRunner implements Runnable {

	private final EncryptPathCommand args;

	public EncryptPathRunner(EncryptPathCommand args) {
		this.args = args;
	}

	@Override
	public void run() {
		try (Passphrase passphrase = args.passphrase()) {
			PathEncryptor.encryptPath(args.vaultLocation(), passphrase, args.cleartextList(), args.outputPath());
		} catch (InvalidPassphraseException e) {
			System.err.println("Invalid passphrase.");
		} catch (AbortCheckException e) {
			System.err.println(e.getMessage());
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}
	}

}
