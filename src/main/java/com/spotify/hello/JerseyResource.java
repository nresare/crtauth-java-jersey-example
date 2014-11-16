package com.spotify.hello;

import com.spotify.crtauth.CrtAuthServer;
import com.spotify.crtauth.exceptions.InvalidInputException;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Response;

/**
 * Authentication web api calls as a Jersey resource
 */
@Path("/")
public class JerseyResource {

  private CrtAuthServer crtAuthServer;

  @SuppressWarnings("UnusedDeclaration")
  @Inject
  public void setCrtAuthServer(CrtAuthServer crtAuthServer) {
    this.crtAuthServer = crtAuthServer;
  }

  @Path("/_auth")
  @GET
  public Response handleAuthentication(@HeaderParam("X-CHAP") String xChap) {
    String[] xChapParts = xChap.split(":");
    try {
      if (xChapParts[0].equals("request")) {
        String challenge = crtAuthServer.createChallenge(xChapParts[1]);
        return Response.ok().header("X-CHAP", "challenge:" + challenge).build();
      } else if (xChapParts[0].equals("response")) {
        String token = crtAuthServer.createToken(xChapParts[1]);
        return Response.ok().header("X-CHAP", "token:" + token).build();
      } else {
        return Response.status(400).entity("Unknown action " + xChapParts[0]).build();
      }
    } catch (InvalidInputException e) {
      throw new RuntimeException(e);
    }

  }

  @Path("/hello")
  @GET
  public String hello(@HeaderParam("Authorization") String authorization) {
    String username;
    try {
      username = crtAuthServer.validateToken(authorization.split(":")[1]);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    return String.format("Hello world, authenticated as %s", username);
  }
}
