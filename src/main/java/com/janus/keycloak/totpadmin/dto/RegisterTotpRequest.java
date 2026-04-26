package com.janus.keycloak.totpadmin.dto;

public class RegisterTotpRequest {
    private String deviceName;
    private String encodedSecret;
    private String initialCode;
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
