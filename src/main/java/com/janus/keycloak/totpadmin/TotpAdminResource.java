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
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import lombok.RequiredArgsConstructor;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class TotpAdminResource {

	private final KeycloakSession session;
	private final RealmModel realm;
	private final AdminPermissionEvaluator auth;

    @Context
    private HttpHeaders headers;

    @GET
    @Path("totp/generate/{user-id}")
    @Produces(MediaType.APPLICATION_JSON)
    public GenerateTotpResponse generate(@PathParam("user-id") String userId) {
        UserModel user = requireUser(realm, userId);
        OTPPolicy policy = realm.getOTPPolicy();

        String secret = TotpUtils.generateSecret();
        String otpAuth = TotpUtils.buildOtpAuthUri(realm.getName(), user.getUsername(), secret, policy);
        String qrCode = TotpUtils.toQrPngBase64(otpAuth);
        return new GenerateTotpResponse(secret, qrCode);
    }

    @POST
    @Path("totp/register/{user-id}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response register(@PathParam("user-id") String userId, RegisterTotpRequest request) {
        UserModel user = requireUser(realm, userId);
        validateRegisterRequest(request);

        String secret = TotpUtils.normalizeSecret(request.getEncodedSecret());
        if (!TotpUtils.isValidInitialCode(request.getInitialCode(), secret, realm.getOTPPolicy())) {
            throw new ApiException(Response.Status.BAD_REQUEST, "Invalid initial TOTP " + request.getInitialCode() + " for the provided secret" + request.getEncodedSecret());
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
    @Path("totp/verify/{user-id}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response verify(@PathParam("user-id") String userId, VerifyTotpRequest request) {
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
    @Path("totp/remove/{user-id}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response removeTotp(@PathParam("user-id") String userId, RemoveTotpRequest request) {
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
    @Path("totp/list/{user-id}")
    public TotpCredentialsResponse getCredentials(@PathParam("user-id") String userId) {
        UserModel user = requireUser(realm, userId);

        List<String> deviceNames = user.credentialManager()
            .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
            .map(this::resolveDeviceName)
            .collect(Collectors.toList());
        return new TotpCredentialsResponse(deviceNames);
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

    private boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}
