package org.computerist.sniexperiments;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.parosproxy.paros.security.SslCertificateService;
import org.parosproxy.paros.security.SslCertificateServiceImpl;
import org.zaproxy.zap.extension.dynssl.SslCertificateUtils;

public class SampleServer {

  public static void main(String[] args) {
    System.out.println("Starting server");
    try {
      // add your ZAP cacert value here
      String ksString = "";
      KeyStore caks = SslCertificateUtils.string2Keystore(ksString);

      SslCertificateServiceImpl scs = (SslCertificateServiceImpl) SslCertificateServiceImpl
        .getService();
      scs.initializeRootCA(caks);

      KeyStore ks = scs.createCertForHost("test1.computerist.org");

      KeyManagerFactory keyFactory = KeyManagerFactory
        .getInstance("SunX509");
      keyFactory.init(ks, SslCertificateService.PASSPHRASE);
      TrustManagerFactory trustFactory = TrustManagerFactory
        .getInstance("SunX509");
      trustFactory.init(ks);

      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(keyFactory.getKeyManagers(),
          trustFactory.getTrustManagers(), null);

      SSLServerSocketFactory sslServerSocketFactory = sslContext
        .getServerSocketFactory();

      SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory
        .createServerSocket(8443);
      while (true) {
        final SSLSocket sslSocket = (SSLSocket) sslServerSocket
          .accept();

        String[] suites = sslSocket.getEnabledCipherSuites();
        for (String suite : suites) {
          System.out.println(suite);
        }

        Thread requestThread = new Thread(new Runnable() {
          @Override
          public void run() {
            final int buf_size = 4096;
            try {
              final InputStream serverIn = sslSocket
          .getInputStream();
        final OutputStream serverOut = sslSocket
          .getOutputStream();

        Socket socket = new Socket("localhost", 80);
        final OutputStream clientOut = socket
          .getOutputStream();
        final InputStream clientIn = socket
          .getInputStream();

        Thread upThread = new Thread(new Runnable() {
          @Override
          public void run() {
            byte[] buf = new byte[buf_size];
            try {
              for (int read = 0; read != -1; read = serverIn
                .read(buf, 0, buf_size)) {
                clientOut.write(buf, 0, read);
                }
            } catch (IOException e) {
              e.printStackTrace();
            }
          }
        });
        upThread.start();

        Thread downThread = new Thread(new Runnable() {
          @Override
          public void run() {
            byte[] buf = new byte[buf_size];
            try {
              for (int read = 0; read != -1; read = clientIn
                .read(buf, 0, buf_size)) {
                serverOut.write(buf, 0, read);
                }
            } catch (IOException e) {
              e.printStackTrace();
            }
          }
        });
        downThread.start();
            } catch (IOException e) {
              // TODO Auto-generated catch block
              e.printStackTrace();
            }
          }
        });
        requestThread.start();
      }
    } catch (Exception exception) {
      exception.printStackTrace();
    }
  }
}