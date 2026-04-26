package com.janus.keycloak.totpadmin.dto;

public class VerifyTotpRequest {
    private String deviceName;
    private String code;

    public String getDeviceName() {
        return deviceName;
    }

    public void setDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }
}
