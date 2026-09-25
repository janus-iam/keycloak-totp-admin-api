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

## Compatibility

The extension is built against the `keycloak.version` property declared in `pom.xml` and is compiled and tested
against every supported Keycloak minor by the [compatibility matrix workflow](.github/workflows/compatibility.yml).

| Keycloak | Status |
|----------|--------|
| 26.3.x, 26.4.x, 26.5.x, 26.6.x, 26.7.x | Supported (tested in CI) |
| <= 26.2.x | Not supported: the admin permission evaluators lived in `org.keycloak.services.resources.admin.permissions` before 26.3.0 and were moved to `org.keycloak.services.resources.admin.fgap` |

To build against a specific version:

```bash
mvn clean package -Dkeycloak.version=26.5.7
```

## Build

```bash
mvn clean package
```

Generated JAR:

`target/keycloak-totp-admin-api-1.2.0-SNAPSHOT.jar`

`mvn process-classes` also writes this extension's OpenAPI document to `target/openapi/openapi.yaml`. Append its paths and components onto a Keycloak Admin OpenAPI file with:

```bash
python3 scripts/merge-openapi.py admin-openapi.yaml target/openapi/openapi.yaml -o admin-with-totp.yaml
```

YAML inputs need PyYAML (`pip install pyyaml`). JSON works with the standard library. The script stops if a path or component name already exists with a different definition.

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
