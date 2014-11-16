package com.spotify.crtauth.example;

import com.spotify.crtauth.CrtAuthClient;
import com.spotify.crtauth.signer.SingleKeySigner;
import com.spotify.crtauth.utils.TraditionalKeyParser;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.RSAPrivateKeySpec;

/**
 * Very simple hello world Jersey
 */
public class HelloClient {

  private static final String PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
      "MIIEogIBAAKCAQEAytMDYYBpRWXwaEQUvjPMBqMjjlbp2GI3mqEVyhSn4cdvPGSK\n" +
      "PO1jHzeouSp1Ex9wP5mJVZyuG4XIUunVBYrGl3FEbxYGOOqVEhri02cU3vWpyCEf\n" +
      "4k/lfvDEQx1330RjgixEFJdJXmE4bdHXO68WluNnfN8gu7rgiEm4FqjgDbzJGWKm\n" +
      "Y2nozjhlaZAKcSxhvCvEbzQQTPE2KhNw0B0skVVOkvR1i21hfovFtoeAi19kLqHX\n" +
      "9HNXXKpX7QpR43SMnnf80CoQKPhQ3CazftmQydJpGC1ZSQ2bi5Pyv70jsA98F4W8\n" +
      "t3HRwrMZ0X8tmJZ7d9VRdGlbZYVuCCfuZjM5swIDAQABAoIBADtnoHbfQHYGDGrN\n" +
      "ffHTg+9xuslG5YjuA3EzuwkMEbvMSOU8YUzFDqInEDDjoZSvQZYvJw0/LbN79Jds\n" +
      "S2srIU1b7HpIzhu/gVfjLgpTB8bh1w95vDfxxLrwU9uAdwqaojaPNoV9ZgzRltB7\n" +
      "hHnDp28cPcRSKekyK+9fAB8K6Uy8N00hojBDwtwXM8C4PpQKod38Vd0Adp9dEdX6\n" +
      "Ro9suYb+d+qFalYbKIbjKWkll+ZiiGJjF1HSQCTwlzS2haPXUlbk57HnN+8ar+a3\n" +
      "ITTc2gbNuTqBRD1V/gCaD9F0npVI3mQ34eUADNVVGS0xw0pN4j++Da8KXP+pyn/G\n" +
      "DU/n8SECgYEA/KN4BTrg/LB7cGrzkMQmW26NA++htjiWHK3WTsQBKBDFyReJBn67\n" +
      "o9kMTHBP35352RfuJ3xEEJ0/ddqGEY/SzNk3HMTlxBbR5Xq8ye102dxfEO3eijJ/\n" +
      "F4VRSf9sFgdRoLvE62qLudytK4Ku9nnKoIqrMxFweTpwxzf2jjIKDbECgYEAzYXe\n" +
      "QxT1A/bfs5Qd6xoCVOAb4T/ALqFo95iJu4EtFt7nvt7avqL+Vsdxu5uBkTeEUHzh\n" +
      "1q47LFoFdGm+MesIIiPSSrbfZJ6ht9kw8EbF8Py85X4LBXey67JlzzUq+ewFEP91\n" +
      "do7uGQAY+BRwXtzzPqaVBVa94YOxdq/AGutrIqMCgYBr+cnQImwKU7tOPse+tbbX\n" +
      "GRa3+fEZmnG97CZOH8OGxjRiT+bGmd/ElX2GJfJdVn10ZZ/pzFii6TI4Qp9OXjPw\n" +
      "TV4as6Sn/EDVXXHWs+BfRKp059VXJ2HeQaKOh9ZAS/x9QANXwn/ZfhGdKQtyWHdb\n" +
      "yiiFeQyjI3EUFD0SZRya4QKBgA1QvQOvmeg12Gx0DjQrLTd+hY/kZ3kd8AUKlvHU\n" +
      "/qzaqD0PhzCOstfAeDflbVGRPTtRu/gCtca71lqidzYYuiAsHfXFP1fvhx64LZmD\n" +
      "nFNurHZZ4jDqfmcS2dHA6hXjGrjtNBkITZjFDtkTyev7eK74b/M2mXrA44CDBnk4\n" +
      "A2rtAoGAMv92fqI+B5taxlZhTLAIaGVFbzoASHTRl3eQJbc4zc38U3Zbiy4deMEH\n" +
      "3QTXq7nxWpE4YwHbgXAeJUGfUpE+nEZGMolj1Q0ueKuSstQg5p1nwhQIxej8EJW+\n" +
      "7siqmOTZDKzieik7KVzaJ/U02Q186smezKIuAOYtT8VCf9UksJ4=\n" +
      "-----END RSA PRIVATE KEY-----";


  private static CrtAuthClient makeCrtAuthClient() {
    PrivateKey privateKey;
    try {
      RSAPrivateKeySpec privateKeySpec = TraditionalKeyParser.parsePemPrivateKey(PRIVATE_KEY);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      privateKey = keyFactory.generatePrivate(privateKeySpec);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    SingleKeySigner singleKeySigner = new SingleKeySigner(privateKey);
    return new CrtAuthClient(singleKeySigner, "localhost");
  }

  private static WebTarget makeWebTarget() {
    Client client = ClientBuilder.newClient();
    return  client.target("http://localhost:8080/");
  }

  public static void main(String[] args) throws Exception {
    WebTarget baseTarget = makeWebTarget();
    CrtAuthClient crtAuthClient = makeCrtAuthClient();

    WebTarget target = baseTarget.path("/_auth");
    log("Requesting challenge from target %s", target.getUri());
    String request = CrtAuthClient.createRequest("test");
    Response httpResponse = target.request().header("X-CHAP", "request:"+ request).get();
    String challenge = httpResponse.getHeaderString("X-CHAP").split(":")[1];
    log("Got challenge %s", challenge);

    String response = crtAuthClient.createResponse(challenge);

    target = baseTarget.path("/_auth");
    httpResponse = target.request().header("X-CHAP", "response:" + response).get();
    String token = httpResponse.getHeaderString("X-CHAP").split(":")[1];
    log("Got token %s", token);

    target = baseTarget.path("/hello");
    String helloOutput = target.request().header("Authorization", "chap:" + token).get().readEntity(String.class);
    log("Output from /hello: " + helloOutput);

  }

  private static void log(String msg, Object... args) {
    System.out.printf(msg + "\n", args);
  }
}
