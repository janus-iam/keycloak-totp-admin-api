package com.janus.keycloak.totpadmin;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class TotpUtilsTest {

    @Test
    void normalizeSecretRemovesSpacesAndUppercases() {
        assertEquals("ABC123DEF", TotpUtils.normalizeSecret("aBc 123 dEf"));
    }

    @Test
    void qrGenerationProducesBase64Payload() {
        String qr = TotpUtils.toQrPngBase64("otpauth://totp/test?secret=ABCDEF");
        assertNotNull(qr);
    }
}
