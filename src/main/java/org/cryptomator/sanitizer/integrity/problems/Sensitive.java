package org.cryptomator.sanitizer.integrity.problems;

import java.util.function.Supplier;

/**
 * A piece of data which may contain sensitive information that the user may wish to keep private.
 */
public interface Sensitive<T> extends Supplier<T> {
}
