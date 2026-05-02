package com.janus.keycloak.totpadmin;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.OTPCredentialModel.SecretEncoding;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.UserPermissionEvaluator;

import com.janus.keycloak.totpadmin.models.GenerateTotpResponse;
import com.janus.keycloak.totpadmin.models.MessageResponse;
import com.janus.keycloak.totpadmin.models.RegisterTotpRequest;
import com.janus.keycloak.totpadmin.models.TotpCredentialsResponse;

import lombok.RequiredArgsConstructor;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Tag(name = "TOTP admin", description = "Register, verify, list, and remove TOTP credentials for a realm user")
@Produces(MediaType.APPLICATION_JSON)
@RequiredArgsConstructor
public class TotpAdminResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    @Context
    private HttpHeaders headers;

    @GET
    @Path("totp/generate/{user-id}")
    @Operation(summary = "Generate a new TOTP secret and QR payload")
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Secret and base64 PNG QR code",
            content = @Content(schema = @Schema(implementation = GenerateTotpResponse.class))),
        @APIResponse(responseCode = "403", description = "Missing permission to manage this user"),
        @APIResponse(responseCode = "404", description = "User not found")
    })
    public GenerateTotpResponse generate(
        @Parameter(description = "User id", required = true) @PathParam("user-id") String userId) {
        UserModel user = requireUserWithManage(realm, userId);
        OTPPolicy policy = realm.getOTPPolicy();

        String secret = TotpUtils.generateSecret();
        String otpAuth = TotpUtils.buildOtpAuthUri(realm.getName(), user.getUsername(), secret, policy);
        String qrCode = TotpUtils.toQrPngBase64(otpAuth);
        return new GenerateTotpResponse(secret, qrCode);
    }

    @POST
    @Path("totp/register/{user-id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Operation(summary = "Register a TOTP credential after the user confirms an initial code")
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Credential stored",
            content = @Content(schema = @Schema(implementation = MessageResponse.class))),
        @APIResponse(responseCode = "400", description = "Invalid request or initial code"),
        @APIResponse(responseCode = "404", description = "User not found"),
        @APIResponse(responseCode = "403", description = "Missing permission to manage this user"),
        @APIResponse(responseCode = "409", description = "Device name already exists")
    })
    public Response register(
        @Parameter(description = "User id", required = true) @PathParam("user-id") String userId,
        RegisterTotpRequest request) {
        UserModel user = requireUserWithManage(realm, userId);
        validateRegisterRequest(request);

        String secret = TotpUtils.normalizeSecret(request.getEncodedSecret());
        if (!TotpUtils.isValidInitialCode(request.getInitialCode(), secret, realm.getOTPPolicy())) {
            throw new ApiException(Response.Status.BAD_REQUEST, "Invalid initial TOTP " + request.getInitialCode() + " for the provided secret " + request.getEncodedSecret());
        }

        Optional<CredentialModel> existing = findByDeviceName(user, request.getDeviceName());
        if (existing.isPresent() && !request.isOverwrite()) {
            throw new ApiException(Response.Status.CONFLICT, "TOTP credential already exists for deviceName");
        }
        existing.ifPresent(credentialModel -> user.credentialManager().removeStoredCredentialById(credentialModel.getId()));

        OTPCredentialModel otpCredential = OTPCredentialModel.createTOTP(
            secret,
            realm.getOTPPolicy().getDigits(),
            realm.getOTPPolicy().getPeriod(),
            realm.getOTPPolicy().getAlgorithm(),
            SecretEncoding.BASE32.name()
        );
        otpCredential.setUserLabel(request.getDeviceName());
        user.credentialManager().createStoredCredential(otpCredential);
        return Response.ok(new MessageResponse("OTP credential registered")).build();
    }

    @POST
    @Path("totp/verify/{user-id}")
    @Operation(summary = "Verify a TOTP code against a stored credential")
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Code is valid",
            content = @Content(schema = @Schema(implementation = MessageResponse.class))),
        @APIResponse(responseCode = "400", description = "Invalid code or missing parameters"),
        @APIResponse(responseCode = "403", description = "Missing permission to view this user"),
        @APIResponse(responseCode = "404", description = "User or credential not found")
    })
    public Response verify(
        @Parameter(description = "User id", required = true) @PathParam("user-id") String userId,
        @Parameter(description = "Credential device label", required = true) @QueryParam("deviceName") String deviceName,
        @Parameter(description = "Current TOTP code", required = true) @QueryParam("code") String code) {
        UserModel user = requireUserWithView(realm, userId);
        if (isBlank(deviceName)) {
            throw new ApiException(Response.Status.BAD_REQUEST, "deviceName is required");
        }
        if (isBlank(code)) {
            throw new ApiException(Response.Status.BAD_REQUEST, "code is required");
        }

        CredentialModel credential = findByDeviceName(user, deviceName)
            .orElseThrow(() -> new ApiException(Response.Status.NOT_FOUND, "TOTP credential not found for deviceName"));

        UserCredentialModel input = new UserCredentialModel(credential.getId(), OTPCredentialModel.TYPE, code);
        if (!user.credentialManager().isValid(input)) {
            throw new ApiException(Response.Status.BAD_REQUEST, "OTP code is invalid");
        }
        return Response.ok(new MessageResponse("OTP code is valid")).build();
    }

    @POST
    @Path("totp/remove/{user-id}")
    @Operation(summary = "Remove a TOTP credential by device label")
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Credential removed",
            content = @Content(schema = @Schema(implementation = MessageResponse.class))),
        @APIResponse(responseCode = "400", description = "Missing deviceName"),
        @APIResponse(responseCode = "403", description = "Missing permission to manage this user"),
        @APIResponse(responseCode = "404", description = "User or credential not found")
    })
    public Response removeTotp(
        @Parameter(description = "User id", required = true) @PathParam("user-id") String userId,
        @Parameter(description = "Credential device label", required = true) @QueryParam("deviceName") String deviceName) {
        UserModel user = requireUserWithManage(realm, userId);
        if (isBlank(deviceName)) {
            throw new ApiException(Response.Status.BAD_REQUEST, "deviceName is required");
        }

        CredentialModel credential = findByDeviceName(user, deviceName)
            .orElseThrow(() -> new ApiException(Response.Status.NOT_FOUND, "TOTP credential not found for deviceName"));
        user.credentialManager().removeStoredCredentialById(credential.getId());
        return Response.ok(new MessageResponse("OTP credential removed")).build();
    }

    @GET
    @Path("totp/list/{user-id}")
    @Operation(summary = "List TOTP device labels for the user")
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Device labels",
            content = @Content(schema = @Schema(implementation = TotpCredentialsResponse.class))),
        @APIResponse(responseCode = "403", description = "Missing permission to view this user"),
        @APIResponse(responseCode = "404", description = "User not found")
    })
    public TotpCredentialsResponse getCredentials(
        @Parameter(description = "User id", required = true) @PathParam("user-id") String userId) {
        UserModel user = requireUserWithView(realm, userId);

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

    /**
     * Same checks as {@code UserResource#credentials()} — list / non-mutating credential reads.
     */
    private UserModel requireUserWithView(RealmModel realm, String userId) {
        UserModel user = requireUser(realm, userId);
        users().requireView(user);
        return user;
    }

    /**
     * Same checks as {@code UserResource#removeCredential} / credential writes — enrollment and removal.
     */
    private UserModel requireUserWithManage(RealmModel realm, String userId) {
        UserModel user = requireUser(realm, userId);
        users().requireManage(user);
        return user;
    }

    private UserPermissionEvaluator users() {
        return auth.users();
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
