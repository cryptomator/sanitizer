package org.cryptomator.sanitizer;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.cryptomator.cryptolib.common.ReseedingSecureRandom;

public class Csprng extends ReseedingSecureRandom {

	public static final Csprng INSTANCE;
	static {
		try {
			INSTANCE = new Csprng();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Java platform is required to support a strong SecureRandom and SHA1PRNG SecureRandom.", e);
		}
	}

	private Csprng() throws NoSuchAlgorithmException {
		super(SecureRandom.getInstanceStrong(), SecureRandom.getInstance("SHA1PRNG"), 1 << 30, 55);
	}

}
