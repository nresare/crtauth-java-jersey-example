package com.spotify.hello;

import com.google.common.io.BaseEncoding;
import com.spotify.crtauth.CrtAuthServer;
import com.spotify.crtauth.exceptions.DeserializationException;
import com.spotify.crtauth.exceptions.InvalidInputException;
import com.spotify.crtauth.exceptions.KeyNotFoundException;
import com.spotify.crtauth.protocol.Challenge;
import com.spotify.crtauth.protocol.Response;
import com.spotify.crtauth.protocol.Token;
import com.spotify.crtauth.protocol.VerifiableMessage;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;

/**
 * Authentication web api calls as a Jersey resource
 */
@Path("/v1")
public class JerseyResource {

  private CrtAuthServer crtAuthServer;

  @SuppressWarnings("UnusedDeclaration")
  @Inject
  public void setCrtAuthServer(CrtAuthServer crtAuthServer) {
    this.crtAuthServer = crtAuthServer;
  }

  @Path("/auth/challenge/{username}")
  @GET
  public String makeChallenge(@PathParam("username") String username) {
    try {
      VerifiableMessage<Challenge> challenge = crtAuthServer.createChallenge(username);
      try {
        return BaseEncoding.base64Url().encode(challenge.serialize());
      } catch (Exception e) {
        throw new Error(e);
      }
    } catch (KeyNotFoundException e) {
      throw new RuntimeException(e);
    }
  }

  @Path("/auth/token/{response}")
  @GET
  public String issueToken(@PathParam("response") String response) {
    Response decodedResponse;
    try {
      decodedResponse = new Response().deserialize(BaseEncoding.base64Url().decode(response));
      return BaseEncoding.base64Url().encode(crtAuthServer.createToken(decodedResponse).serialize());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Path("/hello/{token}")
  @GET
  public String hello(@PathParam("token") String token) {
    String username;
    try {
      VerifiableMessage<Token> tokenDecoder = VerifiableMessage.getDefaultInstance(Token.class);
      byte[] data = BaseEncoding.base64Url().decode(token);
      VerifiableMessage<Token> verifiableToken;
      try {
        verifiableToken = tokenDecoder.deserialize(data);
      } catch (DeserializationException e) {
        throw new InvalidInputException(String.format("failed deserialize token '%s'", token));
      }
      crtAuthServer.validateToken(verifiableToken);
      username = verifiableToken.getPayload().getUserName();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    return String.format("Hello world, authenticated as %s", username);
  }
}
