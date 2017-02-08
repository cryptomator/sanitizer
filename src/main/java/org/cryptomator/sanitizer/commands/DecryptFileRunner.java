package org.cryptomator.sanitizer.commands;

import java.io.IOException;

import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.sanitizer.Passphrase;
import org.cryptomator.sanitizer.integrity.AbortCheckException;
import org.cryptomator.sanitizer.restorer.FileDecryptor;

class DecryptFileRunner implements Runnable {

	private final DecryptFileCommand args;

	public DecryptFileRunner(DecryptFileCommand args) {
		this.args = args;
	}

	@Override
	public void run() {
		try (Passphrase passphrase = args.passphrase()) {
			FileDecryptor.decryptFile(args.vaultLocation(), passphrase);
		} catch (InvalidPassphraseException e) {
			System.err.println("Invalid passphrase.");
		} catch (AbortCheckException e) {
			System.err.println(e.getMessage());
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}
	}

}
