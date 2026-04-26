package com.janus.keycloak.totpadmin;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class TotpAdminRealmResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public TotpAdminRealmResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new TotpAdminResource(session);
    }

    @Override
    public void close() {
        // No-op.
    }
}
