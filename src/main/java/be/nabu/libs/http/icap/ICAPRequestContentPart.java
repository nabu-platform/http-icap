package be.nabu.libs.http.icap;

import java.io.IOException;

import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.core.HTTPFormatter;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.io.api.ByteBuffer;
import be.nabu.utils.io.api.ReadableContainer;
import be.nabu.utils.io.buffers.bytes.ByteBufferFactory;
import be.nabu.utils.mime.api.ContentPart;
import be.nabu.utils.mime.api.Header;
import be.nabu.utils.mime.api.ModifiablePart;
import be.nabu.utils.mime.api.MultiPart;
import be.nabu.utils.mime.impl.MimeHeader;
import be.nabu.utils.mime.impl.PlainMimePart;
import be.nabu.utils.mime.util.ChunkedEncodingReadableByteContainer;

public class ICAPRequestContentPart extends PlainMimePart implements ContentPart {
	
	private int chunkSize = 1024 * 50;
	private HTTPRequest request;
	private byte [] header;

	public ICAPRequestContentPart(HTTPRequest request, MultiPart parent, Header...headers) {
		super(parent, headers);
		this.request = request;
		try {
			ByteBuffer buffer = ByteBufferFactory.getInstance().newInstance();
			new HTTPFormatter(true).formatRequestHeaders(request, buffer);
			header = IOUtils.toBytes(buffer);
			// we calculate the encapsulated
			setHeader(new MimeHeader("Encapsulated", "req-hdr=0, req-body=" + header.length));
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public ReadableContainer<ByteBuffer> getReadable() {
		try {
			ModifiablePart content = request.getContent();
			ReadableContainer<ByteBuffer> readable = (content instanceof ContentPart) ? ((ContentPart) content).getReadable() : null;
			return readable == null 
				? IOUtils.wrap(header, true)
				: IOUtils.chain(true, IOUtils.wrap(header, true), new ChunkedEncodingReadableByteContainer(readable, chunkSize));
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void close() throws IOException {
		request.getContent().close();
	}
}
