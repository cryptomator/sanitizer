package org.cryptomator.sanitizer;

import java.util.Arrays;

/**
 * Autoclosable CharSequence that destroys its content when closed.
 */
public class Passphrase implements CharSequence, AutoCloseable {

	private final char[] chars;

	public Passphrase(char[] chars) {
		this.chars = chars;
	}

	@Override
	public void close() {
		Arrays.fill(chars, ' ');
	}

	@Override
	public int length() {
		return chars.length;
	}

	@Override
	public char charAt(int index) {
		return chars[index];
	}

	@Override
	public Passphrase subSequence(int start, int end) {
		int len = end - start;
		char[] result = new char[len];
		System.arraycopy(chars, start, result, 0, len);
		return new Passphrase(result);
	}

}
