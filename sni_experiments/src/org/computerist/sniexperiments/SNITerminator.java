package org.computerist.sniexperiments;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collection;

import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.StandardConstants;

public class SNITerminator {
  private InetAddress listenAddress;
  private int listenPort;
  private Forwarder forwarder;
  private KeyStore caks;

  public SNITerminator(KeyStore keyStore, InetAddress listenAddress,
      int listenPort, Forwarder forwarder) {
    this.listenAddress = listenAddress;
    this.listenPort = listenPort;
    this.forwarder = forwarder;
    this.caks = keyStore;
  }

  public void start() {
    System.out.println("Starting server");
    try {
      FixedSslCertificateService scs = (FixedSslCertificateService) FixedSslCertificateService
          .getService();
      scs.initializeRootCA(caks);

      KeyStore ks = scs.getHostKeyStore();

      SSLContext sslContext = SSLContext.getInstance("TLS");
      RefreshingKeyManager mgr = new RefreshingKeyManager(ks,
          FixedSslCertificateService.PASSPHRASE, sslContext);

      SSLServerSocketFactory sslServerSocketFactory = sslContext
          .getServerSocketFactory();
      SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory
          .createServerSocket(this.listenPort, 10, this.listenAddress);

      while (true) {
        final SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();

        SSLParameters params = sslSocket.getSSLParameters();

        SNIMatcher matcher = new SNIMatcher(StandardConstants.SNI_HOST_NAME) {
          @Override
          public boolean matches(SNIServerName serverName) {
            synchronized (sslServerSocket) {
              String hostName = new String(serverName.getEncoded());
              try {
                if (!ks.containsAlias(hostName)) {
                  System.out.println(hostName + " is a new alias; adding");
                  scs.createCertForHost(hostName);
                  mgr.refresh();
                }
                mgr.switchAlias(hostName);
              } catch (Exception e) {
                e.printStackTrace();
              }
            }
            return true;
          }
        };
        Collection<SNIMatcher> matchers = new ArrayList<>(1);
        matchers.add(matcher);
        params.setSNIMatchers(matchers);
        sslSocket.setSSLParameters(params);

        final InputStream serverIn = sslSocket.getInputStream();
        final OutputStream serverOut = sslSocket.getOutputStream();

        String host = mgr.getAlias();

        forwarder.forward(serverIn, serverOut, host);
      }
    } catch (Exception exception) {
      exception.printStackTrace();
    }
  }
}
