package org.cryptomator.sanitizer;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class Version {

	private final static String VERSION;
	static {
		String version;
		try (BufferedReader in = new BufferedReader(new InputStreamReader(Version.class.getResourceAsStream("/version.txt"), UTF_8))) {
			version = in.readLine();
		} catch (IOException e) {
			version = "*";
		}
		VERSION = version;
	}

	public static String get() {
		return VERSION;
	}

}
