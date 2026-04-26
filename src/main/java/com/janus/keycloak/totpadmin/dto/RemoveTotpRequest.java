package com.janus.keycloak.totpadmin.dto;

public class RemoveTotpRequest {
    private String deviceName;

    public String getDeviceName() {
        return deviceName;
    }

    public void setDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }
}
