- [x] Deliver a first version with all endpoints working and ship it under v1.0.0

- [x] Secure endpoints using `AdminPermissionEvaluator` (`users().requireView` / `users().requireManage`, aligned with Keycloak `UserResource` credentials)

- [x] Add annotations like Keycloak official repo with :
    - [x] Consumes, Produces, QueryParam
    - [x] @QueryParam to replace `dto` subpackage ?
    - [x] Microprofile OpenAPI schema

- [x] Add more deep unit tests

- [x] Trigger the action to mark that the user has completed or removed any form of TOTP

- [x] Create a compatibility matrix tested by Github Actions

- [x] Subscribe to Keycloak releases with Renovate, test the declared version in CI, and keep compatibility-matrix patches up to date

- [ ] Implement tests with https://github.com/dasniko/testcontainers-keycloak ?

- [ ] Migrate to Gradle ?