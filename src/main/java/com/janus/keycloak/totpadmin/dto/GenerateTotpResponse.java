package com.janus.keycloak.totpadmin.dto;

public class GenerateTotpResponse {
    private final String encodedSecret;
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
