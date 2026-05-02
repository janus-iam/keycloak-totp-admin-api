package com.janus.keycloak.totpadmin.models;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

@Schema(name = "GenerateTotpResponse", description = "New TOTP secret and QR code for enrollment")
public class GenerateTotpResponse {
    @Schema(description = "Base32-encoded secret")
    private final String encodedSecret;
    @Schema(description = "PNG QR image as base64 (otpauth URI embedded)")
    private final String qrCode;

    public GenerateTotpResponse(String encodedSecret, String qrCode) {
        this.encodedSecret = encodedSecret;
        this.qrCode = qrCode;
    }

    public String getEncodedSecret() {
        return encodedSecret;
    }

    public String getQrCode() {
        return qrCode;
    }
}
