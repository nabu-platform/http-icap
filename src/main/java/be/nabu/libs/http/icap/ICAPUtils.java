package be.nabu.libs.http.icap;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.Map;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

import be.nabu.libs.http.HTTPException;
import be.nabu.libs.http.HTTPInterceptorManager;
import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.api.HTTPResponse;
import be.nabu.libs.http.core.DefaultDynamicResourceProvider;
import be.nabu.libs.http.core.DefaultHTTPRequest;
import be.nabu.libs.http.core.HTTPFormatter;
import be.nabu.libs.http.core.HTTPParser;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.mime.api.Header;
import be.nabu.utils.mime.api.ModifiableContentPart;
import be.nabu.utils.mime.impl.MimeHeader;
import be.nabu.utils.mime.impl.MimeUtils;
import be.nabu.utils.mime.impl.PlainMimeContentPart;

public class ICAPUtils {
	
	// if you just want to scan content, regardless of the rest...
	public static VirusInfection scan(InputStream content, String host, String path, boolean secure, SSLContext context, int connectionTimeout, int socketTimeout) {
		int indexOf = host.indexOf(':');
		String requestTarget = indexOf < 0 ? host : host.substring(0, indexOf);
		DefaultHTTPRequest request = new DefaultHTTPRequest("POST", (secure ? "https" : "http") + "://" + requestTarget, 
			new PlainMimeContentPart(null, IOUtils.wrap(content)));
		
		// it normally doesn't matter as the http request doesn't need to be truly valid, but adding it doesn't hurt...
		// because we are using a stream, we don't know the size
		request.getContent().setHeader(new MimeHeader("Transfer-Encoding", "chunked"));
		request.getContent().setHeader(new MimeHeader("Content-Type", "application/octet-stream"));
		return scan(request, host, path, secure, context, connectionTimeout, socketTimeout);
	}
	
	// this creates a new socket _per scan_
	// this is not optimal for heavy volume scanning
	// currently the http client is not retrofitted to support ICAP, more specifically the use of chunked without specifying this in the headers
	// if we add support for that, it "should" work?
	public static VirusInfection scan(HTTPRequest request, String host, String path, boolean secure, SSLContext context, int connectionTimeout, int socketTimeout) {
		try {
			// default port for ICAP
			int port = 1344;
			
			int indexOf = host.indexOf(':');
			if (indexOf > 0) {
				port = Integer.parseInt(host.substring(indexOf + 1));
				host = host.substring(0, indexOf);
			}
			HTTPRequest icap = ICAPUtils.wrap("REQMOD", host + ":" + port, path, request);
			// we're using synchronous I/O, we _need_ to send this! otherwise it will hang...
			icap.getContent().setHeader(new MimeHeader("Connection", "close"));
			
			if (secure && context == null) {
				context = SSLContext.getDefault();
			}
			
			Socket socket = secure ? context.getSocketFactory().createSocket() : new Socket();
			// support for SNI
			if (socket instanceof SSLSocket) {
				SSLParameters sslParameters = new SSLParameters();
				sslParameters.setServerNames(Arrays.asList(new SNIServerName[] { new SNIHostName(host) }));
				((SSLSocket) socket).setSSLParameters(sslParameters);
			}
			socket.connect(new InetSocketAddress(host, port), connectionTimeout);
			socket.setSoTimeout(socketTimeout);
			
			InputStream inputStream = socket.getInputStream();
			OutputStream outputStream = socket.getOutputStream();
			
			icap = HTTPInterceptorManager.intercept(icap);
			
			new HTTPFormatter().formatRequest(icap, IOUtils.wrap(outputStream));
			// make sure all the data is flushed!
			outputStream.flush();
			
			HTTPResponse response = new HTTPParser(new DefaultDynamicResourceProvider(), false).parseResponse(IOUtils.wrap(inputStream), "ICAP");
			outputStream.close();
			socket.close();
			
			// because we back it with a default dynamic resource, we can definitely re-read it
			if (response.getContent() instanceof ModifiableContentPart) {
				((ModifiableContentPart) response.getContent()).setReopenable(true);
			}
			
			response = HTTPInterceptorManager.intercept(response);
			
			return inspect(response);
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public static HTTPRequest wrap(String method, String host, String path, HTTPRequest request) {
		String target = "icap://" + host + "/" + (path == null ? null : path.replaceAll("^[/]+", ""));
		DefaultHTTPRequest wrap = new DefaultHTTPRequest("ICAP", method, target, new ICAPRequestContentPart(request, null), 1.0);
		wrap.getContent().setHeader(new MimeHeader("Host", host));
		return wrap;
	}
	
	// check out https://tools.ietf.org/html/draft-stecher-icap-subid-00#page-9
	public static VirusInfection inspect(HTTPResponse icapResponse) {
		
		if (icapResponse.getCode() >= 400) { 
			throw new HTTPException(icapResponse.getCode(), icapResponse.getMessage());
		}
		
		Header encapsulated = MimeUtils.getHeader("Encapsulated", icapResponse.getContent().getHeaders());
		if (encapsulated == null) {
			throw new IllegalArgumentException("Could not find the 'Encapsulated' header, the response is likely not an ICAP response");
		}
		// some virus scanners (e.g. clamav via squid) return this
		// X-Infection-Found: Type=TypeID; Resolution=ResolutionID; Threat=ThreadDescription;
		Map<String, String> values = MimeUtils.getHeaderAsValues("X-Infection-Found", icapResponse.getContent().getHeaders());
		if (!values.isEmpty()) {
			VirusInfection infection = new VirusInfection();
			for (Map.Entry<String, String> entry : values.entrySet()) {
				if (entry.getKey().equalsIgnoreCase("Resolution")) {
					infection.setResolution(entry.getValue());
				}
				else if (entry.getKey().equalsIgnoreCase("Type")) {
					infection.setType(entry.getValue());
				}
				else if (entry.getKey().equalsIgnoreCase("Threat")) {
					infection.setThreat(entry.getValue());
				}
			}
			return infection;
		}
		// other scanners (e.g. symantec) return this:
		// X-Violations-Found: 1 svwiscd1 EICAR Test String 11101 0
		// X-Violations-Found: <count:numeric> <filename> <description> <id:numeric> <resolutionId:numeric>
		// unfortunately linefeeds are used to separate the values... this is also used for header folding and thus not visible in the end result...
		// additionally you can have multiple threats, which are just added with new linefeeds, making it very hard to parse...
		else {
			Header header = MimeUtils.getHeader("X-Violations-Found", icapResponse.getContent().getHeaders());
			if (header != null) {
				return parseViolationsHeader(header);
			}
		}
		return null;
	}
	
	public static VirusInfection parseViolationsHeader(Header header) {
		// the X-Violations-Found abuses header folding for formatting. however header folding has (so far) never been used structurally and only as a way to avoid old limits on network gear
		// the id and resolution are both numeric, separated by whitespace
		// we are relying on the filename _not_ containing whitespace (it is not clear from the rfc) whereas the description can explicitly contain whitespace (as per the rfc)
		String[] split = header.getValue().split("[0-9]+[\\s]+[0-9]+");
		// we only care about the first one (atm)
		String string = split[0];
		// there will first be a number, then the filename, then the description, so basically two whitespaces (we are assuming)
		String[] split2 = string.split("[\\s]+", 3);
		VirusInfection infection = new VirusInfection();
		infection.setThreat(split2.length >= 3 ? split2[2] : header.getValue());
		return infection;
	}
	
}
