package org.computerist.sniexperiments;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class ServerHarness {
	public static void main(String[] args) {
		try {
			String ZAP_CA = "";
			InetAddress listenAddress = Inet4Address.getByName("0.0.0.0");
			int listenPort = 8443;
			InetAddress proxyAddress = Inet4Address.getLocalHost();
			int proxyPort = 8080;

			SNITerminator terminator = new SNITerminator(ZAP_CA, listenAddress,
					listenPort, proxyAddress, proxyPort);
			terminator.start();
		} catch (UnknownHostException uhe) {
			uhe.printStackTrace();
		}
	}
}
