package com.spotify.crtauth.example;

import com.google.common.io.CharStreams;
import com.spotify.crtauth.CrtAuthServer;
import com.spotify.crtauth.keyprovider.InMemoryKeyProvider;
import com.spotify.crtauth.utils.TraditionalKeyParser;
import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.grizzly2.httpserver.GrizzlyHttpServerFactory;
import org.glassfish.jersey.server.ResourceConfig;

import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.text.SimpleDateFormat;
import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Starts a Jersey crtAuthServer.
 */
public class Server {

  private static final String PUBLIC_KEY;
  static {
    try {
      PUBLIC_KEY = CharStreams.toString(new FileReader("id_rsa.pub"));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }


  public static void main(String[] args) throws IOException {
    configureLogging();
    URI uri = URI.create("http://0.0.0.0:8080/");
    ResourceConfig resourceConfig = new ResourceConfig(JerseyResource.class);

    resourceConfig.registerInstances(new DependencyBinder(makeCrtAuthServer()));

    HttpServer server = GrizzlyHttpServerFactory.createHttpServer(uri, resourceConfig);
    server.start();
    while (true) {
      try {
        Thread.sleep(10000);
      } catch (InterruptedException e) {
        break;
      }
    }
  }

  private static void configureLogging() {
    Logger rootLogger = Logger.getLogger("");
    rootLogger.setLevel(Level.FINE);
    ConsoleHandler ch = new ConsoleHandler();
    ch.setLevel(Level.CONFIG);
    ch.setFormatter(new Formatter() {
      private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
      @Override
      public String format(LogRecord logRecord) {
        return String.format("%s %s %s\n", sdf.format(logRecord.getMillis()),
            logRecord.getLevel().getName(), formatMessage(logRecord));
      }
    });
    for (Handler h : rootLogger.getHandlers()) {
      rootLogger.removeHandler(h);
    }
    rootLogger.addHandler(ch);
  }

  static CrtAuthServer makeCrtAuthServer() {
    InMemoryKeyProvider keyProvider = new InMemoryKeyProvider();

    try {
      RSAPublicKeySpec publicKeySpec = TraditionalKeyParser.parsePemPublicKey(PUBLIC_KEY);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");

      RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
      keyProvider.putKey("test", publicKey);

    } catch (Exception e) {
      throw new RuntimeException(e);
    }


    return new CrtAuthServer.Builder()
        .setServerName("localhost")
        .setKeyProvider(keyProvider)
        .setSecret(new byte[] {(byte)0xde, (byte)0xad, (byte)0xbe, (byte)0xef})
        .build();

  }

  static class DependencyBinder extends AbstractBinder {
    private final CrtAuthServer crtAuthServer;

    public DependencyBinder(CrtAuthServer crtAuthServer) {
      this.crtAuthServer = crtAuthServer;
    }

    @Override
    protected void configure() {
      bind(crtAuthServer).to(CrtAuthServer.class);
    }
  }

}
