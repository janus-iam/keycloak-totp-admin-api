package com.janus.keycloak.totpadmin;

import com.janus.keycloak.totpadmin.dto.GenerateTotpResponse;
import com.janus.keycloak.totpadmin.dto.MessageResponse;
import com.janus.keycloak.totpadmin.dto.RegisterTotpRequest;
import com.janus.keycloak.totpadmin.dto.RemoveTotpRequest;
import com.janus.keycloak.totpadmin.dto.TotpCredentialsResponse;
import com.janus.keycloak.totpadmin.dto.VerifyTotpRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Produces(MediaType.APPLICATION_JSON)
@Path("/totp")
public class TotpAdminResource {

    private static final String REALM_MANAGEMENT_CLIENT = "realm-management";
    private static final String REQUIRED_ADMIN_ROLE = "manage-users";

    private final KeycloakSession session;

    @Context
    private HttpHeaders headers;

    public TotpAdminResource(KeycloakSession session) {
        this.session = session;
    }

    @GET
    @Path("/generate/{user-id}")
    public GenerateTotpResponse generate(@PathParam("user-id") String userId) {
        RealmModel realm = requireRealm();
        requireManageUsersRole(realm);
        UserModel user = requireUser(realm, userId);
        OTPPolicy policy = realm.getOTPPolicy();

        String secret = TotpUtils.generateSecret();
        String otpAuth = TotpUtils.buildOtpAuthUri(realm.getName(), user.getUsername(), secret, policy);
        String qrCode = TotpUtils.toQrPngBase64(otpAuth);
        return new GenerateTotpResponse(secret, qrCode);
    }

    @POST
    @Path("/register/{user-id}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response register(@PathParam("user-id") String userId, RegisterTotpRequest request) {
        RealmModel realm = requireRealm();
        requireManageUsersRole(realm);
        UserModel user = requireUser(realm, userId);
        validateRegisterRequest(request);

        String secret = TotpUtils.normalizeSecret(request.getEncodedSecret());
        if (!TotpUtils.isValidInitialCode(request.getInitialCode(), secret, realm.getOTPPolicy())) {
            throw new ApiException(Response.Status.BAD_REQUEST, "Invalid initial TOTP code");
        }

        Optional<CredentialModel> existing = findByDeviceName(user, request.getDeviceName());
        if (existing.isPresent() && !request.isOverwrite()) {
            throw new ApiException(Response.Status.CONFLICT, "TOTP credential already exists for deviceName");
        }
        existing.ifPresent(credentialModel -> user.credentialManager().removeStoredCredentialById(credentialModel.getId()));

        OTPCredentialModel otpCredential = OTPCredentialModel.createFromPolicy(realm, secret, request.getDeviceName());
        user.credentialManager().createStoredCredential(otpCredential);
        return Response.ok(new MessageResponse("OTP credential registered")).build();
    }

    @POST
    @Path("/verify/{user-id}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response verify(@PathParam("user-id") String userId, VerifyTotpRequest request) {
        RealmModel realm = requireRealm();
        requireManageUsersRole(realm);
        UserModel user = requireUser(realm, userId);
        validateVerifyRequest(request);

        CredentialModel credential = findByDeviceName(user, request.getDeviceName())
            .orElseThrow(() -> new ApiException(Response.Status.NOT_FOUND, "TOTP credential not found for deviceName"));

        if (!user.credentialManager().isValid(UserCredentialModel.otp(request.getCode(), credential.getSecretData()))) {
            throw new ApiException(Response.Status.BAD_REQUEST, "OTP code is invalid");
        }
        return Response.ok(new MessageResponse("OTP code is valid")).build();
    }

    @POST
    @Path("/remove-totp/{user-id}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response removeTotp(@PathParam("user-id") String userId, RemoveTotpRequest request) {
        RealmModel realm = requireRealm();
        requireManageUsersRole(realm);
        UserModel user = requireUser(realm, userId);
        if (request == null || isBlank(request.getDeviceName())) {
            throw new ApiException(Response.Status.BAD_REQUEST, "deviceName is required");
        }

        CredentialModel credential = findByDeviceName(user, request.getDeviceName())
            .orElseThrow(() -> new ApiException(Response.Status.NOT_FOUND, "TOTP credential not found for deviceName"));
        user.credentialManager().removeStoredCredentialById(credential.getId());
        return Response.ok(new MessageResponse("OTP credential removed")).build();
    }

    @GET
    @Path("/get-totp-credentials/{user-id}")
    public TotpCredentialsResponse getCredentials(@PathParam("user-id") String userId) {
        RealmModel realm = requireRealm();
        requireManageUsersRole(realm);
        UserModel user = requireUser(realm, userId);

        List<String> deviceNames = user.credentialManager()
            .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
            .map(this::resolveDeviceName)
            .collect(Collectors.toList());
        return new TotpCredentialsResponse(deviceNames);
    }

    private RealmModel requireRealm() {
        RealmModel realm = session.getContext().getRealm();
        if (realm == null) {
            throw new ApiException(Response.Status.BAD_REQUEST, "Realm context is missing");
        }
        return realm;
    }

    private UserModel requireUser(RealmModel realm, String userId) {
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            throw new ApiException(Response.Status.NOT_FOUND, "User not found");
        }
        return user;
    }

    private void validateRegisterRequest(RegisterTotpRequest request) {
        if (request == null) {
            throw new ApiException(Response.Status.BAD_REQUEST, "Request body is required");
        }
        if (isBlank(request.getDeviceName())) {
            throw new ApiException(Response.Status.BAD_REQUEST, "deviceName is required");
        }
        if (isBlank(request.getEncodedSecret())) {
            throw new ApiException(Response.Status.BAD_REQUEST, "encodedSecret is required");
        }
        if (isBlank(request.getInitialCode())) {
            throw new ApiException(Response.Status.BAD_REQUEST, "initialCode is required");
        }
    }

    private void validateVerifyRequest(VerifyTotpRequest request) {
        if (request == null) {
            throw new ApiException(Response.Status.BAD_REQUEST, "Request body is required");
        }
        if (isBlank(request.getDeviceName())) {
            throw new ApiException(Response.Status.BAD_REQUEST, "deviceName is required");
        }
        if (isBlank(request.getCode())) {
            throw new ApiException(Response.Status.BAD_REQUEST, "code is required");
        }
    }

    private Optional<CredentialModel> findByDeviceName(UserModel user, String deviceName) {
        return user.credentialManager()
            .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
            .filter(credential -> deviceName.equalsIgnoreCase(resolveDeviceName(credential)))
            .findFirst();
    }

    private String resolveDeviceName(CredentialModel credential) {
        return isBlank(credential.getUserLabel()) ? "Unnamed device" : credential.getUserLabel();
    }

    private void requireManageUsersRole(RealmModel realm) {
        AuthenticationManager.AuthResult authResult = new AppAuthManager.BearerTokenAuthenticator(session)
            .setRealm(realm)
            .setConnection(session.getContext().getConnection())
            .setHeaders(headers)
            .authenticate();
        if (authResult == null || authResult.getToken() == null) {
            throw new ApiException(Response.Status.FORBIDDEN, "Admin bearer token is required");
        }

        AccessToken token = authResult.getToken();
        AccessToken.Access resourceAccess = token.getResourceAccess(REALM_MANAGEMENT_CLIENT);
        if (resourceAccess == null || !resourceAccess.isUserInRole(REQUIRED_ADMIN_ROLE)) {
            throw new ApiException(Response.Status.FORBIDDEN, "Missing realm-management/manage-users role");
        }
    }

    private boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}
