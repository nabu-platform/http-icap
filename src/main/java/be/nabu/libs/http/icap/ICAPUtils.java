package be.nabu.libs.http.icap;

import java.util.Map;

import be.nabu.libs.http.api.HTTPRequest;
import be.nabu.libs.http.api.HTTPResponse;
import be.nabu.libs.http.core.DefaultHTTPRequest;
import be.nabu.utils.mime.api.Header;
import be.nabu.utils.mime.impl.MimeHeader;
import be.nabu.utils.mime.impl.MimeUtils;

public class ICAPUtils {
	public static HTTPRequest wrap(String method, String host, String path, HTTPRequest request) {
		String target = "icap://" + host + "/" + (path == null ? null : path.replaceAll("^[/]+", ""));
		DefaultHTTPRequest wrap = new DefaultHTTPRequest("ICAP", method, target, new ICAPRequestContentPart(request, null), 1.0);
		wrap.getContent().setHeader(new MimeHeader("Host", host));
		return wrap;
	}
	
	public static VirusInfection inspect(HTTPResponse icapResponse) {
		Header encapsulated = MimeUtils.getHeader("Encapsulated", icapResponse.getContent().getHeaders());
		if (encapsulated == null) {
			throw new IllegalArgumentException("Could not find the 'Encapsulated' header, the response is likely not an ICAP response");
		}
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
		return null;
	}
}
