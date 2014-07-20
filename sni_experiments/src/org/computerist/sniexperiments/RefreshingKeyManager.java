package org.computerist.sniexperiments;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509KeyManager;

/*
 * At the moment, this just dumps output on calls and allows for alias
 * switching. This will allow itself to refresh its mgr attr when new items
 * are added to a keystore.
 */
public class RefreshingKeyManager implements X509KeyManager {

  private X509KeyManager mgr;
  private String alias;

  public RefreshingKeyManager(X509KeyManager mgr) {
    this.mgr = mgr;
  }

  @Override
  public String chooseClientAlias(String[] arg0, Principal[] arg1, Socket arg2) {
    System.out.println("chooseClientlAlias: " + arg0);
    if (null != arg1) {
      for (Principal principal : arg1) {
        System.out.println("  Principal: " + principal);
      }
    }
    return mgr.chooseClientAlias(arg0, arg1, arg2);
  }

  @Override
  public String chooseServerAlias(String arg0, Principal[] arg1, Socket arg2) {
    System.out.println("chooseServerAlias: " + arg0);
    if (null != arg1) {
      for (Principal principal : arg1) {
        System.out.println("  Principal: " + principal);
      }
    }
    String serverAlias = mgr.chooseServerAlias(arg0, arg1, arg2);
    if(null!=serverAlias) {
      System.out.println("Switching aliases");
      serverAlias = this.alias;
    }
    System.out.println("server alias is: "+serverAlias);
    return serverAlias;
  }

  @Override
  public X509Certificate[] getCertificateChain(String arg0) {
    System.out.println("getting chain for " + arg0);
    X509Certificate[] certs = mgr.getCertificateChain(arg0);
    for(X509Certificate cert : certs) {
      System.out.println(cert);
    }
    return certs;
  }

  @Override
  public String[] getClientAliases(String keyType, Principal[] issuers) {
    System.out.println("getClientAliases " + keyType);
    return mgr.getClientAliases(keyType, issuers);
  }

  @Override
  public PrivateKey getPrivateKey(String alias) {
    System.out.println("getPrivateKey " + alias);
    return mgr.getPrivateKey(alias);
  }

  @Override
  public String[] getServerAliases(String keyType, Principal[] issuers) {
    System.out.println("getServerAliases: " + keyType);
    if (null != issuers) {
      for (Principal principal : issuers) {
        System.out.println("  Principal: " + principal);
      }
    }
    return mgr.getServerAliases(keyType, issuers);
  }

  public void switchAlias(String hostName) {
    this.alias = hostName;
  }
}
