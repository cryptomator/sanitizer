package org.cryptomator.sanitizer.integrity.problems;

import static java.lang.String.format;
import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.WRITE;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.OpenOption;
import java.nio.file.Path;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileHeader;

class FileSizeOfZeroInHeaderProblemSolution implements Solution {

	private final Sensitive<Path> file;

	public FileSizeOfZeroInHeaderProblemSolution(Sensitive<Path> file) {
		this.file = file;
	}

	@Override
	public void execute(SolutionContext c) {
		try {
			c.start("Fix zero file size in header for %s", file);
			try (SeekableByteChannel channel = FileChannel.open(file.get(), openOptions(c))) {
				final FileHeader header = readHeader(c, channel);
				header.setFilesize(-1L);
				writeHeader(c, channel, header);
			}
			c.finish();
		} catch (IOException | AuthenticationFailedException e) {
			c.fail(e);
		}
	}

	private OpenOption[] openOptions(SolutionContext c) {
		if (c.dryRun()) {
			return new OpenOption[] {READ};
		} else {
			return new OpenOption[] {READ, WRITE};
		}
	}

	private FileHeader readHeader(SolutionContext c, ReadableByteChannel channel) throws IOException {
		ByteBuffer headerBuf = ByteBuffer.allocate(c.cryptor().fileHeaderCryptor().headerSize());
		int read = channel.read(headerBuf);
		if (read != c.cryptor().fileHeaderCryptor().headerSize()) {
			throw new IllegalStateException(format("Failed to read all header bytes from %s", file));
		}
		headerBuf.flip();
		return c.cryptor().fileHeaderCryptor().decryptHeader(headerBuf);
	}

	private void writeHeader(SolutionContext c, SeekableByteChannel channel, FileHeader header) throws IOException {
		channel.position(0L);
		ByteBuffer headerBuf = c.cryptor().fileHeaderCryptor().encryptHeader(header);
		if (!c.dryRun()) {
			channel.write(headerBuf);
		}
	}

}
