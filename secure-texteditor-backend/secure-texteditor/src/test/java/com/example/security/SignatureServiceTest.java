package com.example.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.SignatureException;

import static org.junit.jupiter.api.Assertions.*;

class SignatureServiceTest {

    private SignatureService signatureService;

    @BeforeEach
    void setUp() {
        signatureService = new SignatureService();
    }

    /** ✅ Testet das Signieren und Verifizieren mit DSA */
    @Test
    void testSignAndVerifyDSA() throws Exception {
        String text = "Test Nachricht";
        String algorithm = "SHA256withDSA";

        String signature = signatureService.signText(text, algorithm);
        assertNotNull(signature, "Signatur sollte nicht null sein");

        boolean isValid = signatureService.verifySignature(text, algorithm, signature);
        assertTrue(isValid, "Signatur sollte gültig sein");
    }

    /** ✅ Testet das Signieren und Verifizieren mit ECDSA */
    @Test
    void testSignAndVerifyECDSA() throws Exception {
        String text = "Test Nachricht";
        String algorithm = "SHA256withECDSA";

        String signature = signatureService.signText(text, algorithm);
        assertNotNull(signature, "Signatur sollte nicht null sein");

        boolean isValid = signatureService.verifySignature(text, algorithm, signature);
        assertTrue(isValid, "Signatur sollte gültig sein");
    }

    /** ❌ Testet, ob das Verifizieren einer manipulierten Nachricht fehlschlägt */
    @Test
    void testVerifyTamperedMessageFails() throws Exception {
        String originalText = "Originale Nachricht";
        String manipulatedText = "Manipulierte Nachricht";
        String algorithm = "SHA256withDSA";

        String signature = signatureService.signText(originalText, algorithm);
        assertNotNull(signature);

        boolean isValid = signatureService.verifySignature(manipulatedText, algorithm, signature);
        assertFalse(isValid, "Signatur sollte ungültig sein");
    }

    /** ❌ Testet, ob eine falsche Signatur fehlschlägt */
    @Test
    void testVerifyInvalidSignatureFails() throws Exception {
        String text = "Test Nachricht";
        String algorithm = "SHA256withDSA";

        // Erstelle eine ungültige Signatur (zufällige Bytes, keine echte Signatur)
        byte[] invalidSignatureBytes = "invalid_signature".getBytes();
        String invalidSignature = Base64.getEncoder().encodeToString(invalidSignatureBytes);

        // Überprüfung, ob die Methode eine SignatureException auslöst
        Exception exception = assertThrows(SignatureException.class, () -> {
            signatureService.verifySignature(text, algorithm, invalidSignature);
        });

        assertTrue(exception.getMessage().contains("error decoding signature bytes"), 
            "SignatureException sollte mit 'error decoding signature bytes' auftreten");
    }


    /** ❌ Testet, ob ein nicht unterstützter Algorithmus eine Exception wirft */
    @Test
    void testSignWithInvalidAlgorithm() {
        String text = "Test Nachricht";
        String invalidAlgorithm = "INVALID-ALGO";

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            signatureService.signText(text, invalidAlgorithm);
        });

        assertTrue(exception.getMessage().contains("Nicht unterstützter Algorithmus"),
                "Fehlermeldung sollte passenden Hinweis enthalten");
    }

    /**
     * ❌ Testet, ob ein nicht unterstützter Algorithmus bei Verifizierung eine
     * Exception wirft
     */
    @Test
    void testVerifyWithInvalidAlgorithm() {
        String text = "Test Nachricht";
        String invalidAlgorithm = "INVALID-ALGO";
        String fakeSignature = Base64.getEncoder().encodeToString("invalid_signature".getBytes());

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            signatureService.verifySignature(text, invalidAlgorithm, fakeSignature);
        });

        assertTrue(exception.getMessage().contains("Nicht unterstützter Algorithmus"),
                "Fehlermeldung sollte passenden Hinweis enthalten");
    }

    /** ✅ Testet die Generierung eines Schlüsselpaares für DSA */
    @Test
    void testGenerateKeyPairDSA() throws Exception {
        Method method = signatureService.getClass().getDeclaredMethod("generateKeyPair", String.class);
        method.setAccessible(true); // Erlaubt Zugriff auf private Methode

        KeyPair keyPair = (KeyPair) method.invoke(signatureService, "SHA256withDSA");

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
    }

    /** ✅ Testet die Generierung eines Schlüsselpaares für ECDSA */
    @Test
    void testGenerateKeyPairECDSA() throws Exception {
        Method method = signatureService.getClass().getDeclaredMethod("generateKeyPair", String.class);
        method.setAccessible(true); // Erlaubt Zugriff auf private Methode

        KeyPair keyPair = (KeyPair) method.invoke(signatureService, "SHA256withECDSA");

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
    }

}
