/*
* Copyright (C) 2020 Alexander Verbruggen
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package be.nabu.libs.http.icap;

import java.io.ByteArrayInputStream;

import be.nabu.libs.http.core.DefaultHTTPRequest;
import be.nabu.utils.io.IOUtils;
import be.nabu.utils.mime.impl.PlainMimeContentPart;
import junit.framework.TestCase;

// can only run these tests with a valid scanner...
// originally tested with a scanner on a remote machine tunneled via SSH
public class Test2 extends TestCase {
	
	public void testMaliciousRequest() {
		try {
			// EICAR test string: X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
			byte [] test = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".getBytes();
			DefaultHTTPRequest request = new DefaultHTTPRequest("POST", "https://www.example.com", new PlainMimeContentPart(null, IOUtils.wrap(test, true)));
			VirusInfection scan = ICAPUtils.scan(request, "localhost:1344", "/squidclamav", false, null, 30000, 60000);
			System.out.println("request scan is: " + scan);
		}
		catch (Exception e) {
			// ignore :(
			System.out.println("testMaliciousRequest could not be tested");
		}
	}
	
	public void testOkContentRequest() {
		try {
			byte [] test = "test".getBytes();
			DefaultHTTPRequest request = new DefaultHTTPRequest("POST", "https://www.example.com", new PlainMimeContentPart(null, IOUtils.wrap(test, true)));
			VirusInfection scan = ICAPUtils.scan(request, "localhost:1344", "/squidclamav", false, null, 30000, 60000);
			System.out.println("request scan is: " + scan);
		}
		catch (Exception e) {
			// ignore :(
			System.out.println("testOkContentRequest could not be tested");
		}
	}
	
	public void testMaliciousStream() {
		try {
			byte [] test = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".getBytes();
			VirusInfection scan = ICAPUtils.scan(new ByteArrayInputStream(test), "localhost:1344", "/squidclamav", false, null, 30000, 60000);
			System.out.println("stream scan is: " + scan);
		}
		catch (Exception e) {
			// ignore :(
			System.out.println("testMaliciousStream could not be tested");
		}
	}
	
	public void testOkStream() {
		try {
			byte [] test = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H".getBytes();
			VirusInfection scan = ICAPUtils.scan(new ByteArrayInputStream(test), "localhost:1344", "/squidclamav", false, null, 30000, 60000);
			System.out.println("stream scan is: " + scan);
		}
		catch (Exception e) {
			// ignore :(
			System.out.println("testOkStream could not be tested");
		}
	}
}
