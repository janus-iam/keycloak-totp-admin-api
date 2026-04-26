package com.janus.keycloak.totpadmin.dto;

import java.util.List;

public class TotpCredentialsResponse {
    private final List<String> deviceName;

    public TotpCredentialsResponse(List<String> deviceName) {
        this.deviceName = deviceName;
    }

    public List<String> getDeviceName() {
        return deviceName;
    }
}
