package com.janus.keycloak.totpadmin;

import com.janus.keycloak.totpadmin.models.MessageResponse;
import com.janus.keycloak.totpadmin.models.RegisterTotpRequest;
import jakarta.ws.rs.core.Response;
import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.TimeBasedOTP;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.UserPermissionEvaluator;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Locale;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TotpAdminResourceTest {

    private static final String USER_ID = "11111111-2222-3333-4444-555555555555";

    @Mock
    private KeycloakSession session;
    @Mock
    private RealmModel realm;
    @Mock
    private AdminPermissionEvaluator auth;
    @Mock
    private UserPermissionEvaluator userPermissions;
    @Mock
    private UserModel user;
    @Mock
    private UserProvider userProvider;
    @Mock
    private SubjectCredentialManager credentialManager;
    @Mock
    private OTPPolicy otpPolicy;

    private TotpAdminResource resource;

    @BeforeEach
    void setUp() {
        resource = new TotpAdminResource(session, realm, auth);
        when(session.users()).thenReturn(userProvider);
        when(userProvider.getUserById(realm, USER_ID)).thenReturn(user);
        lenient().when(auth.users()).thenReturn(userPermissions);
        lenient().when(user.credentialManager()).thenReturn(credentialManager);
        lenient().when(realm.getOTPPolicy()).thenReturn(otpPolicy);
        lenient().when(otpPolicy.getAlgorithm()).thenReturn("HmacSHA1");
        lenient().when(otpPolicy.getDigits()).thenReturn(6);
        lenient().when(otpPolicy.getPeriod()).thenReturn(30);
        lenient().when(otpPolicy.getLookAheadWindow()).thenReturn(1);
    }

    @Test
    void verifyRejectsNullDeviceNameQueryParam() {
        ApiException ex = assertThrows(ApiException.class,
            () -> resource.verify(USER_ID, null, "123456"));
        assertBadRequest(ex, "deviceName is required");
    }

    @Test
    void verifyRejectsEmptyDeviceNameQueryParam() {
        ApiException ex = assertThrows(ApiException.class,
            () -> resource.verify(USER_ID, "", "123456"));
        assertBadRequest(ex, "deviceName is required");
    }

    @Test
    void verifyRejectsWhitespaceOnlyDeviceNameQueryParam() {
        ApiException ex = assertThrows(ApiException.class,
            () -> resource.verify(USER_ID, "   ", "123456"));
        assertBadRequest(ex, "deviceName is required");
    }

    @Test
    void verifyRejectsNullCodeQueryParam() {
        ApiException ex = assertThrows(ApiException.class,
            () -> resource.verify(USER_ID, "my-device", null));
        assertBadRequest(ex, "code is required");
    }

    @Test
    void verifyRejectsEmptyCodeQueryParam() {
        ApiException ex = assertThrows(ApiException.class,
            () -> resource.verify(USER_ID, "my-device", ""));
        assertBadRequest(ex, "code is required");
    }

    @Test
    void verifyRejectsWhitespaceOnlyCodeQueryParam() {
        ApiException ex = assertThrows(ApiException.class,
            () -> resource.verify(USER_ID, "my-device", "\t"));
        assertBadRequest(ex, "code is required");
    }

    @Test
    void removeRejectsNullDeviceNameQueryParam() {
        ApiException ex = assertThrows(ApiException.class,
            () -> resource.removeTotp(USER_ID, null));
        assertBadRequest(ex, "deviceName is required");
    }

    @Test
    void removeRejectsEmptyDeviceNameQueryParam() {
        ApiException ex = assertThrows(ApiException.class,
            () -> resource.removeTotp(USER_ID, ""));
        assertBadRequest(ex, "deviceName is required");
    }

    @Test
    void removeRejectsWhitespaceOnlyDeviceNameQueryParam() {
        ApiException ex = assertThrows(ApiException.class,
            () -> resource.removeTotp(USER_ID, "  \n"));
        assertBadRequest(ex, "deviceName is required");
    }

    @Test
    void removeUnknownDeviceReturnsNotFound() {
        when(credentialManager.getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE))
            .thenReturn(Stream.empty());

        ApiException ex = assertThrows(ApiException.class,
            () -> resource.removeTotp(USER_ID, "no-such-device"));
        assertNotFound(ex, "TOTP credential not found for deviceName");
        verify(credentialManager).getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE);
        verify(credentialManager, never()).removeStoredCredentialById(any());
    }

    @Test
    void registerSameDeviceTwiceWithoutOverwriteReturnsConflict() {
        String deviceName = "existing-phone";
        CredentialModel existing = mock(CredentialModel.class);
        when(existing.getUserLabel()).thenReturn(deviceName);
        when(credentialManager.getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE))
            .thenReturn(Stream.of(existing));

        String secret = TotpUtils.generateSecret();
        String initialCode = new TimeBasedOTP("HmacSHA1", 6, 30, 1).generateTOTP(base32SecretBytes(secret));

        RegisterTotpRequest request = new RegisterTotpRequest();
        request.setDeviceName(deviceName);
        request.setEncodedSecret(secret);
        request.setInitialCode(initialCode);
        request.setOverwrite(false);

        ApiException ex = assertThrows(ApiException.class, () -> resource.register(USER_ID, request));
        assertConflict(ex, "TOTP credential already exists for deviceName");
        verify(credentialManager).getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE);
        verify(credentialManager, never()).removeStoredCredentialById(any());
        verify(credentialManager, never()).createStoredCredential(any());
        verify(user, never()).removeRequiredAction(anyString());
    }

    @Test
    void registerSameDeviceTwiceWithOverwriteReplacesCredential() {
        String deviceName = "replace-me";
        CredentialModel existing = mock(CredentialModel.class);
        when(existing.getUserLabel()).thenReturn(deviceName);
        when(existing.getId()).thenReturn("old-cred-id");
        when(credentialManager.getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE))
            .thenReturn(Stream.of(existing));

        String secret = TotpUtils.generateSecret();
        String initialCode = new TimeBasedOTP("HmacSHA1", 6, 30, 1).generateTOTP(base32SecretBytes(secret));

        RegisterTotpRequest request = new RegisterTotpRequest();
        request.setDeviceName(deviceName);
        request.setEncodedSecret(secret);
        request.setInitialCode(initialCode);
        request.setOverwrite(true);

        Response response = resource.register(USER_ID, request);
        assertEquals(Response.Status.OK.getStatusCode(), response.getStatus());
        verify(credentialManager).removeStoredCredentialById("old-cred-id");
        verify(credentialManager).createStoredCredential(any(OTPCredentialModel.class));
        verify(user).removeRequiredAction(eq(UserModel.RequiredAction.CONFIGURE_TOTP.name()));
    }

    private static void assertBadRequest(ApiException ex, String expectedMessage) {
        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), ex.getResponse().getStatus());
        assertInstanceOf(MessageResponse.class, ex.getResponse().getEntity());
        assertEquals(expectedMessage, ((MessageResponse) ex.getResponse().getEntity()).getMessage());
    }

    private static void assertConflict(ApiException ex, String expectedMessage) {
        assertEquals(Response.Status.CONFLICT.getStatusCode(), ex.getResponse().getStatus());
        assertInstanceOf(MessageResponse.class, ex.getResponse().getEntity());
        assertEquals(expectedMessage, ((MessageResponse) ex.getResponse().getEntity()).getMessage());
    }

    private static void assertNotFound(ApiException ex, String expectedMessage) {
        assertEquals(Response.Status.NOT_FOUND.getStatusCode(), ex.getResponse().getStatus());
        assertInstanceOf(MessageResponse.class, ex.getResponse().getEntity());
        assertEquals(expectedMessage, ((MessageResponse) ex.getResponse().getEntity()).getMessage());
    }

    private static byte[] base32SecretBytes(String encodedSecret) {
        String normalized = encodedSecret.replace(" ", "").toUpperCase(Locale.ROOT);
        int padding = (8 - normalized.length() % 8) % 8;
        return new Base32().decode(normalized + "=".repeat(padding));
    }
}
