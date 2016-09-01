package org.cryptomator.sanitizer.integrity.problems;

public enum Severity {

	/**
	 * Issues which prevent the integrity check from operating correctly.
	 */
	FATAL,

	/**
	 * Issues which are guaranteed to cause problems while using the vault.
	 */
	ERROR,

	/**
	 * Issues which are not guaranteed to cause problems while using the vault.
	 */
	WARN,

	/**
	 * Issues which occur during normal operation of the vault.
	 */
	INFO

}
