# Keycloak TOTP Admin API Extension

Keycloak Quarkus extension exposing admin-only endpoints for TOTP credential lifecycle operations.

## Endpoints

All endpoints are available under:

`/admin/realms/{realm}/authentication/totp/{operation}/{user-id}`

- `GET /generate/{user-id}`
- `POST /register/{user-id}`
- `POST /verify/{user-id}`
- `POST /remove/{user-id}`
- `GET /list/{user-id}`

## Build

```bash
mvn clean package
```

Generated JAR:

`target/keycloak-totp-admin-api-1.0.0-SNAPSHOT.jar`

## Local Docker Test Environment

Use the provided `docker-compose.yml` to run the official Keycloak image with this extension mounted in the providers folder.

1. Build the extension JAR:

```bash
mvn clean package
```

2. Start Keycloak locally:

```bash
docker compose up --watch
```

> the `--watch` should restart the container when the `.jar` changes but instead it makes the container crash, so you will have to restart it by hand !

3. Open Keycloak:

`http://localhost:8080`

Default admin credentials:

- username: `admin`
- password: `admin`

5. Stop the environment:

```bash
docker compose down
```

## Deploy to Keycloak (Quarkus)

1. Copy JAR into Keycloak `providers/` directory.
2. Run build step:

```bash
bin/kc.sh build
```

3. Start Keycloak:

```bash
bin/kc.sh start
```

## Verification Checklist

1. Generate secret and QR.
2. Register credential with current authenticator code.
3. Verify code succeeds.
4. List includes registered `deviceName`.
5. Remove credential.
6. List no longer includes the removed `deviceName`.
