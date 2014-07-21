package org.computerist.sniexperiments;

/*
 * Get a socket via HTTP CONNECT.
 * Derived from from: https://code.google.com/p/java-socket-over-http-proxy-connect/
 *                  : http://stackoverflow.com/a/15869788
 */

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.SocketException;

public final class ProxyConnectSocketFactory {
  public static Socket GetSocket(String host, int port) throws IOException {
    /*************************
     * Get the jvm arguments
     *************************/

    int proxyPort = Integer.parseInt(System.getProperty("http.proxyPort"));
    String proxyHost = System.getProperty("http.proxyHost");
    return GetSocket(host, port, proxyHost, proxyPort);
  }

  public static Socket GetSocket(String host, int port, String proxyHost,
      int proxyPort) throws IOException {
    // Socket object connecting to proxy
    Socket sock = new Socket(proxyHost, proxyPort);

    /***********************************
     * HTTP CONNECT protocol RFC 2616
     ***********************************/
    String proxyConnect = "CONNECT " + host + ":" + port+" HTTP/1.1" + "\n\n";

    //System.out.println(proxyConnect);
    sock.getOutputStream().write(proxyConnect.getBytes());
    /***********************************/

    /***************************
     * validate HTTP response.
     ***************************/
    byte[] tmpBuffer = new byte[512];
    InputStream socketInput = sock.getInputStream();

    int len = socketInput.read(tmpBuffer, 0, tmpBuffer.length);

    if (len == 0) {
      throw new SocketException("Invalid response from proxy");
    }

    String proxyResponse = new String(tmpBuffer, 0, len, "UTF-8");

    // Expecting HTTP/1.x 200 OK
    if (proxyResponse.indexOf("200") != -1) {

      // Flush any outstanding message in buffer
      if (socketInput.available() > 0)
        socketInput.skip(socketInput.available());

      // Proxy Connect Successful, return the socket for IO
      return sock;
    } else {
      throw new ProxyConnectSocketException("Fail to create Socket",
          proxyResponse);
    }
  }

  /**
   * Simplest Base64 Encoder adopted from GeorgeK
   * 
   * @see http
   *      ://stackoverflow.com/questions/469695/decode-base64-data-in-java/4265472
   *      #4265472
   */
  private static class Base64 {
    /***********************
     * Base64 character set
     ***********************/
    private final static char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .toCharArray();

    /**
     * Translates the specified byte array into Base64 string.
     * 
     * @param buf
     *          the byte array (not null)
     * @return the translated Base64 string (not null)
     */
    public static String encode(byte[] buf) {
      int size = buf.length;
      char[] ar = new char[((size + 2) / 3) * 4];
      int a = 0;
      int i = 0;
      while (i < size) {
        byte b0 = buf[i++];
        byte b1 = (i < size) ? buf[i++] : 0;
        byte b2 = (i < size) ? buf[i++] : 0;

        int mask = 0x3F;
        ar[a++] = ALPHABET[(b0 >> 2) & mask];
        ar[a++] = ALPHABET[((b0 << 4) | ((b1 & 0xFF) >> 4)) & mask];
        ar[a++] = ALPHABET[((b1 << 2) | ((b2 & 0xFF) >> 6)) & mask];
        ar[a++] = ALPHABET[b2 & mask];
      }
      switch (size % 3) {
      case 1:
        ar[--a] = '=';
      case 2:
        ar[--a] = '=';
      }
      return new String(ar);
    }
  }
}

class ProxyConnectSocketException extends IOException {
  public ProxyConnectSocketException(String string, String proxyResponse) {
    super(string + ": " + proxyResponse);
  }

  /**
   * 
   */
  private static final long serialVersionUID = 191084721553349199L;

}