package org.cryptomator.sanitizer.integrity.problems;

import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.WRITE;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;

import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileHeader;

class FileSizeInHeaderProblemSolution implements Solution {

	private final Sensitive<Path> file;

	public FileSizeInHeaderProblemSolution(Sensitive<Path> file) {
		this.file = file;
	}

	@Override
	public void execute(SolutionContext c) {
		try {
			c.start("Fix file size in header for %s", file);
			try (FileChannel ch = FileChannel.open(file.get(), READ, WRITE)) {
				// read header:
				ByteBuffer headerBuf = ByteBuffer.allocate(c.cryptor().fileHeaderCryptor().headerSize());
				ch.read(headerBuf);
				headerBuf.flip();
				FileHeader header = c.cryptor().fileHeaderCryptor().decryptHeader(headerBuf);
				long cleartextSize = header.getFilesize();
				long actualSize = Files.size(file.get());
				if (cleartextSize > actualSize) {
					c.fail("Skipping file with invalid file size %s/%s", cleartextSize, actualSize);
					return;
				}
				int headerSize = c.cryptor().fileHeaderCryptor().headerSize();
				int ciphertextChunkSize = c.cryptor().fileContentCryptor().ciphertextChunkSize();
				int cleartextChunkSize = c.cryptor().fileContentCryptor().cleartextChunkSize();
				long newCiphertextSize = Cryptors.ciphertextSize(cleartextSize, c.cryptor());
				long newEOF = headerSize + newCiphertextSize;
				long newFullChunks = newCiphertextSize / ciphertextChunkSize; // int-truncation
				long newAdditionalCiphertextBytes = newCiphertextSize % ciphertextChunkSize;
				if (newAdditionalCiphertextBytes == 0) {
					// (new) last block is already correct. just truncate:
					ch.truncate(newEOF);
				} else {
					// last block may contain padding and needs to be re-encrypted:
					long lastChunkIdx = newFullChunks;
					long beginOfLastChunk = headerSize + lastChunkIdx * ciphertextChunkSize;
					assert beginOfLastChunk < newEOF;
					int lastCleartextChunkLength = (int) (cleartextSize % cleartextChunkSize);
					assert lastCleartextChunkLength < cleartextChunkSize;
					assert lastCleartextChunkLength > 0;
					ch.position(beginOfLastChunk);
					ByteBuffer lastCiphertextChunk = ByteBuffer.allocate(ciphertextChunkSize);
					int read = ch.read(lastCiphertextChunk);
					if (read != -1) {
						lastCiphertextChunk.flip();
						ByteBuffer lastCleartextChunk = c.cryptor().fileContentCryptor().decryptChunk(lastCiphertextChunk, lastChunkIdx, header, true);
						lastCleartextChunk.position(0).limit(lastCleartextChunkLength);
						assert lastCleartextChunk.remaining() == lastCleartextChunkLength;
						ByteBuffer newLastChunkCiphertext = c.cryptor().fileContentCryptor().encryptChunk(lastCleartextChunk, lastChunkIdx, header);
						ch.truncate(beginOfLastChunk);
						ch.write(newLastChunkCiphertext);
					} else {
						c.fail("Reached EOF at position %s/%s", beginOfLastChunk, newEOF);
						return; // must exit method before changing header!
					}
				}
				header.setFilesize(-1l);
				ByteBuffer newHeaderBuf = c.cryptor().fileHeaderCryptor().encryptHeader(header);
				ch.position(0);
				ch.write(newHeaderBuf);
			}
			c.finish();
		} catch (IOException | AuthenticationFailedException e) {
			c.fail(e);
		}
	}

}
