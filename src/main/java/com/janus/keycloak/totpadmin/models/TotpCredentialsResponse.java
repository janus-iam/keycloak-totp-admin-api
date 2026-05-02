package com.janus.keycloak.totpadmin.models;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

import java.util.List;

@Schema(name = "TotpCredentialsResponse", description = "TOTP credentials registered for the user")
public class TotpCredentialsResponse {
    @Schema(description = "Device labels for each stored TOTP credential")
    private final List<String> deviceName;

    public TotpCredentialsResponse(List<String> deviceName) {
        this.deviceName = deviceName;
    }

    public List<String> getDeviceName() {
        return deviceName;
    }
}
