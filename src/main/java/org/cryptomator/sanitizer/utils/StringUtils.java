package org.cryptomator.sanitizer.utils;

import static java.util.Arrays.fill;

public class StringUtils {

	public static String repeat(char c, int amount) {
		if (amount < 0) {
			throw new IllegalArgumentException("amount: " + amount);
		}
		char[] result = new char[amount];
		fill(result, c);
		return new String(result);
	}

	public static String cutOfAtEnd(String value, String end) {
		if (value.endsWith(end)) {
			return value.substring(0, value.length() - end.length());
		} else {
			return value;
		}
	}

	public static String cutOfAtStart(String start, String value) {
		if (value.startsWith(start)) {
			return value.substring(start.length());
		} else {
			return value;
		}
	}

}
