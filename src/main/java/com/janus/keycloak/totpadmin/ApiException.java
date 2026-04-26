package com.janus.keycloak.totpadmin;

import com.janus.keycloak.totpadmin.dto.MessageResponse;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

public class ApiException extends WebApplicationException {

    public ApiException(Response.Status status, String message) {
        super(Response.status(status).entity(new MessageResponse(message)).build());
    }
}
