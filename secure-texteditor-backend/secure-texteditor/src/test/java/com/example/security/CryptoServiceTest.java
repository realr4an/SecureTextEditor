package com.example.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import javax.crypto.SecretKey;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class CryptoServiceTest {

    private CryptoService cryptoService;

    @BeforeEach
    void setUp() {
        cryptoService = new CryptoService();
    }

    @Test
    void testGenerateKeyWithoutPassword() throws Exception {
        SecretKey key = cryptoService.generateKey("AES", 256, null, null);
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(32, key.getEncoded().length);
    }

    @Test
    void testGenerateKeyWithPassword() throws Exception {
        char[] password = "securePassword".toCharArray();
        byte[] salt = new byte[16];

        SecretKey key = cryptoService.generateKey("AES", 256, password, salt);
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(32, key.getEncoded().length);
    }

    @Test
    void testEncryptAndDecryptAES_CBC() throws Exception {
        String plaintext = "Test message";
        String algorithm = "AES";
        String mode = "CBC";
        String padding = "PKCS5Padding";
        int keyLength = 128;
        char[] password = null;

        Map<String, String> encryptionResult = cryptoService.encrypt(algorithm, mode, padding, keyLength, plaintext,
                password);

        assertNotNull(encryptionResult.get("encrypted"));
        assertNotNull(encryptionResult.get("key"));
        assertNotNull(encryptionResult.get("iv"));

        String encryptedText = encryptionResult.get("encrypted");
        String key = encryptionResult.get("key");
        String iv = encryptionResult.get("iv");

        String decryptedText = cryptoService.decrypt(algorithm, mode, padding, keyLength, encryptedText, iv, "", key,
                "", null);
        assertEquals(plaintext, decryptedText);
    }

    @Test
    void testEncryptAndDecryptChaCha20() throws Exception {
        String plaintext = "Test message";
        String algorithm = "ChaCha20";
        int keyLength = 256;
        char[] password = null;

        // Encryption
        Map<String, String> encryptionResult = cryptoService.encrypt(algorithm, "None", "NoPadding", keyLength, plaintext,
                password);

        assertNotNull(encryptionResult.get("encrypted"));
        assertNotNull(encryptionResult.get("key"));
        assertNotNull(encryptionResult.get("iv"));

        String encryptedText = encryptionResult.get("encrypted");
        String key = encryptionResult.get("key");
        String iv = encryptionResult.get("iv");

        // Decryption - Achtung: Modus "" (leer) statt "None"
        String decryptedText = cryptoService.decrypt(algorithm, "", "", keyLength, encryptedText, iv, "", key,
                "", null);

        assertEquals(plaintext, decryptedText);
    }

    @Test
    void testEncryptionFailsWithInvalidIV() {
        String algorithm = "AES";
        String mode = "GCM"; // GCM erfordert ein IV
        String padding = "NoPadding";
        int keyLength = 128;
        char[] password = null;

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            // IV explizit als null setzen, um den Fehler auszulösen
            cryptoService.decrypt(algorithm, mode, padding, keyLength, "invalidCipher", null, "", "invalidKey", "",
                    password);
        });

        // Sicherstellen, dass die Exception-Meldung existiert
        assertNotNull(exception.getMessage(), "Die Exception-Nachricht darf nicht null sein!");

        // Erwartete und tatsächliche Fehlermeldung prüfen (mit der exakten Formulierung
        // aus der Exception)
        assertTrue(exception.getMessage().contains("Kein IV vorhanden, aber für diesen Modus erforderlich!"),
                "Fehlermeldung sollte 'Kein IV vorhanden, aber für diesen Modus erforderlich!' enthalten, aber war: "
                        + exception.getMessage());
    }

    @Test
    void testGenerateMAC_SHA256() throws Exception {
        String message = "Hello World";
        SecretKey key = cryptoService.generateKey("AES", 256, null, null);

        String mac = cryptoService.generateMAC(message, key, "SHA-256");
        assertNotNull(mac);
        assertFalse(mac.isEmpty());
    }

    @Test
    void testGenerateMAC_HMAC_SHA256() throws Exception {
        String message = "Hello World";
        SecretKey key = cryptoService.generateKey("AES", 256, null, null);

        String mac = cryptoService.generateMAC(message, key, "HMAC-SHA256");
        assertNotNull(mac);
        assertFalse(mac.isEmpty());
    }

    @Test
    void testGenerateMAC_InvalidAlgorithm() throws Exception {
        String message = "Hello World";
        SecretKey key = cryptoService.generateKey("AES", 256, null, null);

        // Erwartet, dass eine IllegalArgumentException geworfen wird
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            cryptoService.generateMAC(message, key, "INVALID-ALGO");
        });

        // Sicherstellen, dass die Fehlermeldung den erwarteten Text enthält
        assertNotNull(exception.getMessage());
        assertTrue(exception.getMessage().contains("Unbekannter MAC-Algorithmus"),
                "Fehlermeldung sollte 'Unbekannter MAC-Algorithmus' enthalten, aber war: " + exception.getMessage());
    }

}
