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
      String ksString = "_u3-7QAAAAIAAAABAAAAAQARb3dhc3BfemFwX3Jvb3RfY2EAAAFERpzkrAAABQEwggT9MA4GCisGAQQBKgIRAQEFAASCBOkGot-di3E0L-m_L2Bf68KxE13QKZ-zIImItTZ5zEMGsiI4RApZNy9o16rRPmcuAU32sb-Q7MipBctPTcxjvTlLNV50SY4nkgy3kqe4NrwbcJy8aiCFGTgNwMC8_18tBb0sFu4CEpGVS0wuKjmNTBbj664ouoG62QEj7cF1mUKxtUs5b2OilPty049do9vDrJo0G7rB44qOg9jUf1HAY_bHYBNmQ5Uorhs0d1wT689N9Wc1JaJklkeMNMdg9Y_r-UlaPrqjpB-pj_L3bK-zEuAXFuMGD3FfYFhyHnn2MmwLO0v71E61QJEA8hSiy-0sUoZQ4Ag9q99WWlTf3YuWEiW_fks50YoPLI5u1OnKT_FVHS3GPKpgCsL7EtHEj3U-jfdSVzXpm8J0v_PyEuTN5_55Q3aPQaRiUGsr-qbx4m73814ASlEyCsPiM1k4OIP07JT9NsT30m0uirz0x8nVjABPN9oIvCdT58zVZL7BosRX_N6k8XRK6jWaEix1efLhYUBvuXSF_EyTr8EqQALE62zRkfc8QM5KfdC1jdEDQnRvnZm2vqKHj06ibJXv5gUMDeDTrf4Pnh6TjkAJUnUcGUaeuspRnfaGZG90foCNKErexkFK_YmTo9RF_Dm6V0ICMf25LsfkajW6DsEmWDQkjUqoImfAo6X_UX-M21PJjK_J3KO4VHXC4Sw8YiAB6pIGPM-xEE-yb7Jv9neqXmBYS3dV1F_gw3JbF8MPdghHCHy0uWWuzjSkXwToECwmYi2fDkvN6alu_KBGO-5NkBZZQ7wuI0mO7QESOikIoP1dr0bMFdatT_8GXCWyfIb8kaiki2Dks2VawvxSuON8cqKbN5tOSy-oYb0CnvKRw6FAascmsiWTKtV91RN24mZcwgBoAqd0kPm7sXUaqMVz0HqMM3skFVJTOWnwFpZM3os3KhmsZp_wWmGzHDr2exujlkEqSVjky-VUsucQS9bca0jirTAgks3PFlAkQuE0IhsN2Xk8k4aoGqStAsSLxFwBPo6tvBS7Gq03tmKmbyVoKexuBfKqkeZqFR3Rl7R_01Dd7GOTyZv48IW8rZPNSuv6ilJD7nTAxZ8PhhWmYCVY8mjkKJIf9TOMSdJ3-v16wzVIGpDjwoWXo0WmW48g9W1r17ooqrKF-uIchMBeEKCYCf-je9lJanAbUQu5ZTneUQ7I9FXc332pjq01aOunDBiUdNevSqjODQyIHWGPgjTOFf_yGJsvgkVmBWewboLq7Y4aJvy4H7TWkP427DaTl_17R9JQ2I1wWYmoLvn5NO0QjBviNp6Et2_QnR914Yrvi2SVh0OEnsYZwEb0gvle49eAelA8RbwKECtEvDhkCaQLesXb8Nz-We3kc0CRPr2RqKEsN35YgQSSu6SG_9bNrtc1wmgsHMCUffz6EcgmFHa_k80OwR8u6MLY9RbT36z1GeT07Vj4bpl4XjJ9gF2TCWaot9hxUbzNXuYjd2SIoIBVx5OyaFYe19bb3-erofuvLAsQ93Uv-ru0AaNJSzA7RJXa8DKpQrvfeG0nYdm63XKxdLyDz99E1PLSW766f1nhw3zYqn8bfTPwZUoCalRBSXGXwc0WsSnBXXdmxi1OyyZaODh3dHtfJgzBD_EQ1zNjIgdDaMzXvF64peWbN1SUB7Alk8feEmZJjqVmKO50D7cAAAABAAVYLjUwOQAAA_IwggPuMIIC1qADAgECAgQU10blMA0GCSqGSIb3DQEBBQUAMIGFMScwJQYDVQQDDB5PV0FTUCBaZWQgQXR0YWNrIFByb3h5IFJvb3QgQ0ExGTAXBgNVBAcMEDQ3Mzc1MGYyZjkxYWNjNTMxFjAUBgNVBAoMDU9XQVNQIFJvb3QgQ0ExGjAYBgNVBAsMEU9XQVNQIFpBUCBSb290IENBMQswCQYDVQQGEwJ4eDAeFw0xNDAyMTgyMDA4MDVaFw0xNTAyMTgyMDA4MDVaMIGFMScwJQYDVQQDDB5PV0FTUCBaZWQgQXR0YWNrIFByb3h5IFJvb3QgQ0ExGTAXBgNVBAcMEDQ3Mzc1MGYyZjkxYWNjNTMxFjAUBgNVBAoMDU9XQVNQIFJvb3QgQ0ExGjAYBgNVBAsMEU9XQVNQIFpBUCBSb290IENBMQswCQYDVQQGEwJ4eDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKEPI8JEZIpMI50oi0ZzQwIV3UhT4Sp40hhbjHTEqOI83UhU3SRO_Qi7EN_R_w6SQLOi78iNGufLa1etsQXYEZQ997B731yqIRl1hK9e24Tgy2HkmIuX_j8pkDIDIF4adUSZ30O8Hmxf4zk46HgawEvp6S77RP-thS94eWBehV72GXlhU2Ga8_jtr_4pBregqMxqqLx25ZVhaOSI2aE_rC5ioUpPJbuAT4AiPti8li5HMlp49YzQFc_5mjL3gqwqsOILF1ZzxMy6gX5AlM6mrB3b5Y3rIgz1GUlnT7uQSVOT0-JppZwGxCU3exQ4EbwMa-uUwXZZ7wZvyxgFNK3Y-CUCAwEAAaNkMGIwHQYDVR0OBBYEFFZlOVGMzC6Vv_-Hajki5QBoT8LFMA8GA1UdEwEB_wQFMAMBAf8wCwYDVR0PBAQDAgG2MCMGA1UdJQQcMBoGCCsGAQUFBwMBBggrBgEFBQcDAgYEVR0lADANBgkqhkiG9w0BAQUFAAOCAQEAEup1I4EdVLUIyadGHfS5ngLN3S2dacRh6L8AGhSyEb_-bQEkjCcyJgWOQk_1w9MhuycWR9YR0d2In89iAT4BNl002ygNOTNAHyMJrauZK2t-PS6b0wxPqxv2jJ-3OQQDBqNsencTnT6xyOTLU-qwPtYvOaCcHLkLMJ2bnkERswz2eKHEO2UU2bQ5EVHtuazHAQxpx7yQeE8dZFQBEXmzy8Ks4Sg0Vx5BiMCc3AHMwC4mic_K3hB_JQ1oK32rhoF_aqRJUpIRAIsihVMRxhHxXOFahUwKG_pa_SPYzfc9mEw7HgdZWu75WBdb2otFPD9CVoz8DHHmWf1dF8u4I4a7lH1FPBIm9AH42ojvkZkgUv2ehnR3";
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