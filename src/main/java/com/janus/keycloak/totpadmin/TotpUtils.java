package com.janus.keycloak.totpadmin;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.apache.commons.codec.binary.Base32;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.utils.TimeBasedOTP;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Locale;

public final class TotpUtils {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int SECRET_BYTES = 20;

    private TotpUtils() {
    }

    public static String generateSecret() {
        byte[] bytes = new byte[SECRET_BYTES];
        RANDOM.nextBytes(bytes);
        return new Base32().encodeToString(bytes).replace("=", "");
    }

    public static String normalizeSecret(String encodedSecret) {
        return encodedSecret == null ? null : encodedSecret.replace(" ", "").toUpperCase(Locale.ROOT);
    }

    public static String buildOtpAuthUri(String realmName, String username, String secret, OTPPolicy policy) {
        String issuer = urlEncode(realmName);
        String label = urlEncode(realmName + ":" + username);
        return "otpauth://totp/" + label
            + "?secret=" + secret
            + "&issuer=" + issuer
            + "&algorithm=" + policy.getAlgorithm()
            + "&digits=" + policy.getDigits()
            + "&period=" + policy.getPeriod();
    }

    public static String toQrPngBase64(String content) {
        try {
            QRCodeWriter writer = new QRCodeWriter();
            BitMatrix matrix = writer.encode(content, BarcodeFormat.QR_CODE, 300, 300);
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(matrix, "PNG", stream);
            return Base64.getEncoder().encodeToString(stream.toByteArray());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate QR code", e);
        }
    }

    public static boolean isValidInitialCode(String code, String encodedSecret, OTPPolicy policy) {
        if (!isSixToEightDigits(code)) {
            return false;
        }
        TimeBasedOTP validator = new TimeBasedOTP(
            policy.getAlgorithm(),
            policy.getDigits(),
            policy.getPeriod(),
            policy.getLookAheadWindow()
        );
        try {
            return validator.validateTOTP(code, decodeBase32Secret(encodedSecret));
        } catch (Exception ex) {
            return false;
        }
    }

    public static boolean isValidTotpCode(String code, String encodedSecret, OTPPolicy policy) {
        if (!isSixToEightDigits(code)) {
            return false;
        }
        TimeBasedOTP validator = new TimeBasedOTP(
            policy.getAlgorithm(),
            policy.getDigits(),
            policy.getPeriod(),
            policy.getLookAheadWindow()
        );
        try {
            return validator.validateTOTP(code, decodeBase32Secret(encodedSecret));
        } catch (Exception ex) {
            return false;
        }
    }

    private static boolean isSixToEightDigits(String code) {
        return code != null && code.matches("^\\d{6,8}$");
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static byte[] decodeBase32Secret(String encodedSecret) {
        String normalizedSecret = normalizeSecret(encodedSecret);
        int paddingLength = (8 - normalizedSecret.length() % 8) % 8;
        String paddedSecret = normalizedSecret + "=".repeat(paddingLength);
        return new Base32().decode(paddedSecret);
    }
}
