- [x] Deliver a first version with all endpoints working and ship it under v1.0.0

- [ ] Create a compatibility matrix tested by Github Actions

- [ ] Suscribe to keycloak new version, test it and update the matrix

- [ ] Trigger the action to mark that the user has completed or removed any form of TOTP

- [ ] Implement tests with https://github.com/dasniko/testcontainers-keycloak ?

- [ ] Secure endpoints using `AdminPermissionEvaluator`  with `auth.realm().requireViewRequiredActions();`  or something like this

- [x] Add annotations like Keycloak official repo with :
    - [x] Consumes, Produces, QueryParam
    - [x] @QueryParam to replace `dto` subpackage ?
    - [x] Microprofile OpenAPI schema

- [ ] Migrate to Gradle