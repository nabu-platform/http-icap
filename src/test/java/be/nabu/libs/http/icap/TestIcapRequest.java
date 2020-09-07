package be.nabu.libs.http.icap;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.text.ParseException;

import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.api.HTTPResponse;
import be.nabu.libs.http.client.connections.PlainConnectionHandler;
import be.nabu.libs.http.core.DefaultDynamicResourceProvider;
import be.nabu.libs.http.core.DefaultHTTPRequest;
import be.nabu.libs.http.core.HTTPFormatter;
import be.nabu.libs.http.core.HTTPParser;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.mime.impl.FormatException;
import be.nabu.utils.mime.impl.MimeHeader;
import be.nabu.utils.mime.impl.PlainMimeContentPart;
import junit.framework.TestCase;

public class TestIcapRequest extends TestCase {
	@SuppressWarnings("resource")
	public void testRequest() throws IOException, FormatException, ParseException {
		byte [] test = "test".getBytes();
		
		// the sneaky stuff!
		test = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".getBytes();
		DefaultHTTPRequest request = new DefaultHTTPRequest("POST", "https://www.google.com", new PlainMimeContentPart(null, IOUtils.wrap(test, true)));
		
//		HTTPRequest wrap = ICAPUtils.wrap("REQMOD", "172.16.11.19:1344", "/SYMCScanReq-AV", request);
//		HTTPRequest wrap = ICAPUtils.wrap("REQMOD", "neo-dev.cubitec.be:1344", "/REQMOD", request);
		HTTPRequest wrap = ICAPUtils.wrap("REQMOD", "neo-dev.cubitec.be:1344", "/squidclamav", request);
		
		wrap.getContent().setHeader(new MimeHeader("Connection", "Close"));
		
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		new HTTPFormatter().formatRequest(wrap, IOUtils.wrap(output));
		System.out.println(new String(output.toByteArray()));
		
		PlainConnectionHandler handler = new PlainConnectionHandler(null, 30000, 30000);
		Socket connect = handler.connect("localhost", 1344, false);
		InputStream inputStream = connect.getInputStream();
		OutputStream outputStream = connect.getOutputStream();
		IOUtils.copyBytes(IOUtils.wrap(output.toByteArray(), true), IOUtils.wrap(outputStream));
		byte[] bytes = IOUtils.toBytes(IOUtils.wrap(inputStream));
		outputStream.close();
		System.out.println(new String(bytes));
		connect.close();
		
		HTTPResponse parseResponse = new HTTPParser(new DefaultDynamicResourceProvider(), false).parseResponse(IOUtils.wrap(bytes, true), "ICAP");
		System.out.println("parsed: " + ICAPUtils.inspect(parseResponse));
	}
	
	public void testResponse() {
		String response = "ICAP/1.0 200 OK\n" + 
				"Date: Mon, 10 Jan 2000  09:55:21 GMT\n" + 
				"Server: ICAP-Server-Software/1.0\n" + 
				"Connection: close\n" + 
				"ISTag: \"W3E4R7U9-L2E4-2\"\n" + 
				"Encapsulated: req-hdr=0, req-body=244\n" + 
				"\n" + 
				"POST /origin-resource/form.pl HTTP/1.1\n" + 
				"Host: www.origin-server.com\n" + 
				"Via: 1.0 icap-server.net (ICAP Example ReqMod Service 1.1)\n" + 
				"Accept: text/html, text/plain, image/gif\n" + 
				"Accept-Encoding: gzip, compress\n" + 
				"Pragma: no-cache\n" + 
				"Content-Length: 45\n" + 
				"\n" + 
				"2d\n" + 
				"I am posting this information.  ICAP powered!\n" + 
				"0";
		
	}
}