package com.janus.keycloak.totpadmin.models;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

@Schema(name = "MessageResponse")
public class MessageResponse {
    @Schema
    private final String message;

    public MessageResponse(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}
