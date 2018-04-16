package org.cryptomator.sanitizer.utils;

import com.google.common.io.BaseEncoding;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.regex.Pattern.CASE_INSENSITIVE;
import static org.cryptomator.sanitizer.utils.StringUtils.*;

public class NameUtil {

	private static final Pattern PATTERN = Pattern.compile("^(([A-Z2-7]{8}){3,}[A-Z2-7=]{1,8}).*", CASE_INSENSITIVE);

	public static Optional<String> decryptablePartOfName(String name) {
		String result = name;
		result = cutOfAtEnd(result, ".lng");
		result = cutOfAtStart("0", result);
		Matcher matcher = PATTERN.matcher(result);
		if (matcher.matches()) {
			result = matcher.group(1);
			result = result + repeat('=', numMissing(result));
			result = result.toUpperCase();
			return Optional.of(result);
		} else {
			return Optional.empty();
		}
	}

	public static int numMissing(String name) {
		if (name.startsWith("0")) {
			return (8 - (name.length() - 1) % 8) % 8;
		} else {
			return (8 - name.length() % 8) % 8;
		}
	}

	public static String mFileHash(String correctName) {
		try {
			MessageDigest sha1 = MessageDigest.getInstance("SHA1");
			return BaseEncoding.base32().encode(sha1.digest(correctName.getBytes(StandardCharsets.UTF_8)));
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
}
