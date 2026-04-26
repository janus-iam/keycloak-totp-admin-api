package com.janus.keycloak.totpadmin;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class TotpAdminRealmResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "authentication";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new TotpAdminRealmResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        // No-op.
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No-op.
    }

    @Override
    public void close() {
        // No-op.
    }

    @Override
    public String getId() {
        return ID;
    }
}
