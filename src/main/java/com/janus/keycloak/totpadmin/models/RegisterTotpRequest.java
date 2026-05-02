package com.janus.keycloak.totpadmin.models;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

@Schema(name = "RegisterTotpRequest", description = "Payload to confirm and store a generated TOTP secret")
public class RegisterTotpRequest {
    @Schema(required = true)
    private String deviceName;
    @Schema(required = true, description = "Base32-encoded secret from the generate step")
    private String encodedSecret;
    @Schema(required = true, description = "One-time code from the authenticator, matching the secret")
    private String initialCode;
    @Schema(description = "If true, replace an existing credential with the same device name")
    private boolean overwrite;

    public String getDeviceName() {
        return deviceName;
    }

    public void setDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }

    public String getEncodedSecret() {
        return encodedSecret;
    }

    public void setEncodedSecret(String encodedSecret) {
        this.encodedSecret = encodedSecret;
    }

    public String getInitialCode() {
        return initialCode;
    }

    public void setInitialCode(String initialCode) {
        this.initialCode = initialCode;
    }

    public boolean isOverwrite() {
        return overwrite;
    }

    public void setOverwrite(boolean overwrite) {
        this.overwrite = overwrite;
    }
}
