package org.computerist.sniexperiments;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

import org.parosproxy.paros.security.SslCertificateService;
import org.parosproxy.paros.security.SslCertificateServiceImpl;
import org.zaproxy.zap.extension.dynssl.SslCertificateUtils;

public class SampleServer {
  
  private static RefreshingKeyManager reInit(SSLContext sslContext, KeyStore ks) throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, KeyManagementException{
    
    KeyManagerFactory keyFactory = KeyManagerFactory
      .getInstance("SunX509");
    keyFactory.init(ks, SslCertificateService.PASSPHRASE);

    System.out.println("there are "+keyFactory.getKeyManagers().length+" managers");
    RefreshingKeyManager mgr = new RefreshingKeyManager((X509KeyManager) keyFactory.getKeyManagers()[0]);
    KeyManager[] managers = {mgr};
    // TODO: experiment with custom KeyManagers
    sslContext.init(managers, null, null);
    return mgr;
  }

  public static void main(String[] args) {
    System.out.println("Starting server");
    try {
      // add your ZAP cacert value here
      String ksString = "";
      KeyStore caks = SslCertificateUtils.string2Keystore(ksString);

      SslCertificateServiceImpl scs = (SslCertificateServiceImpl) SslCertificateServiceImpl
        .getService();
      scs.initializeRootCA(caks);

      KeyStore ks = scs.createCertForHost("some.sample.domain.example.com");

      SSLContext sslContext = SSLContext.getInstance("TLS");
      RefreshingKeyManager mgr = reInit(sslContext, ks);
      
      SSLContext clientContext = SSLContext.getInstance("TLS");
      TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
      tmf.init(caks);
      clientContext.init(null, tmf.getTrustManagers(), null);
      SSLSocketFactory clientSSLSocketFactory = clientContext.getSocketFactory();

      SSLServerSocketFactory sslServerSocketFactory = sslContext
        .getServerSocketFactory();

      InetAddress[] addresses = Inet4Address.getAllByName("0.0.0.0");
      SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory
        .createServerSocket(8443, 10, addresses[0]);
      
      while (true) {
        final SSLSocket sslSocket = (SSLSocket) sslServerSocket
          .accept();

        SSLParameters params = sslSocket.getSSLParameters();
        
        SNIMatcher matcher = new SNIMatcher(StandardConstants.SNI_HOST_NAME){
          @Override
          public boolean matches(SNIServerName serverName) {
            String hostName = new String(serverName.getEncoded());
            System.out.println(hostName);
            try {
              if(!ks.containsAlias(hostName)){
                System.out.println(hostName+" is a new alias; adding");
                scs.createCertForHost(hostName);
              }
              /* 
               * perhaps, since our key manager is magic, we can avoid re-initing the whole context and just 
               * replace its mgr attribute with a new one from our KMF(which is, re-init-ed)
               */
              RefreshingKeyManager mgr2 = reInit(sslContext, ks);
              mgr2.switchAlias(hostName);
            } catch (Exception e) {
              // TODO Auto-generated catch block
              e.printStackTrace();
            } 
            return true;
          }
        };
        Collection<SNIMatcher> matchers = new ArrayList<>(1);
        matchers.add(matcher);
        params.setSNIMatchers(matchers);
        sslSocket.setSSLParameters(params);

        Thread requestThread = new Thread(new Runnable() {
          @Override
          public void run() {
            final int buf_size = 4096;
            try {
              final InputStream serverIn = sslSocket
          .getInputStream();
        final OutputStream serverOut = sslSocket
          .getOutputStream();
        
        String host = mgr.getAlias();
        Socket plainSocket = ProxyConnectSocketFactory.GetSocket(host, 443, "localhost", 8080);
        
        Socket socket = clientSSLSocketFactory.createSocket(plainSocket, null,
            plainSocket.getPort(), false);
        
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