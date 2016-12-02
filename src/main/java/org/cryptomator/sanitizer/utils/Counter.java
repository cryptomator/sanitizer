package org.cryptomator.sanitizer.utils;

public class Counter {

	private long count = 0;

	public void increment() {
		count++;
	}

	public long get() {
		return count;
	}

}
