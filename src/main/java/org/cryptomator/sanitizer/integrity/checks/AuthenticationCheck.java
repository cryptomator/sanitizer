package org.cryptomator.sanitizer.integrity.checks;

import static java.nio.file.StandardOpenOption.READ;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Path;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.sanitizer.integrity.problems.Problems;

class AuthenticationCheck implements Check {

	private final Cryptor cryptor;
	private final boolean alsoCheckContent;

	public AuthenticationCheck(Cryptor cryptor, boolean alsoCheckContent) {
		this.cryptor = cryptor;
		this.alsoCheckContent = alsoCheckContent;
	}

	@Override
	public void checkThrowingExceptions(Problems problems, Path path) throws IOException {
		ByteBuffer headerBuf = ByteBuffer.allocate(cryptor.fileHeaderCryptor().headerSize());
		ByteBuffer contentBuf = ByteBuffer.allocate(cryptor.fileContentCryptor().ciphertextChunkSize());
		try (ReadableByteChannel in = FileChannel.open(path, READ)) {
			int read = in.read(headerBuf);
			if (read != cryptor.fileHeaderCryptor().headerSize()) {
				problems.reportSizeMismatch(path, "at least 88 bytes", read);
				return;
			}
			headerBuf.flip();
			final FileHeader header;
			try {
				header = cryptor.fileHeaderCryptor().decryptHeader(headerBuf);
			} catch (AuthenticationFailedException e) {
				problems.reportUnauthenticFileHeader(path);
				return;
			}
			long filesize = header.getFilesize();
			if (filesize != -1L) {
				problems.reportFileSizeInHeader(path, filesize);
			}
			long chunkNumber = 0;
			while (alsoCheckContent && (read = in.read(contentBuf)) > 0) {
				contentBuf.flip();
				try {
					cryptor.fileContentCryptor().decryptChunk(contentBuf, chunkNumber, header, true);
				} catch (AuthenticationFailedException e) {
					problems.reportUnauthenticFileContent(path, chunkNumber);
				}
				contentBuf.clear();
				chunkNumber++;
			}
		}
	}

}
