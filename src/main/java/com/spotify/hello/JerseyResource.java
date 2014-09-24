package com.spotify.hello;

import com.spotify.crtauth.CrtAuthServer;
import com.spotify.crtauth.exceptions.InvalidInputException;
import com.spotify.crtauth.exceptions.KeyNotFoundException;

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
      return crtAuthServer.createChallenge(username);
    } catch (KeyNotFoundException e) {
      throw new RuntimeException(e);
    }
  }

  @Path("/auth/token/{response}")
  @GET
  public String issueToken(@PathParam("response") String response) {
    try {
      return crtAuthServer.createToken(response);
    } catch (InvalidInputException e) {
      throw new RuntimeException(e);
    }
  }

  @Path("/hello/{token}")
  @GET
  public String hello(@PathParam("token") String token) {
    String username;
    try {
      username = crtAuthServer.validateToken(token);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    return String.format("Hello world, authenticated as %s", username);
  }
}
