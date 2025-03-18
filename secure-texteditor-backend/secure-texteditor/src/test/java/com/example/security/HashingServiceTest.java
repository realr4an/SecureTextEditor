package com.example.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class HashingServiceTest {

    private HashingService hashingService;

    @BeforeEach
    void setUp() {
        hashingService = new HashingService();
    }

    /** ✅ Testet SHA-256 Hash-Generierung */
    @Test
    void testGenerateSHA256Hash() throws Exception {
        String message = "TestMessage";
        String hash = hashingService.generateHash(message, "SHA-256");

        assertNotNull(hash);
        assertFalse(hash.isEmpty());
    }

    /** ✅ Testet HMAC-SHA256 Hash-Generierung */
    @Test
    void testGenerateHmacSHA256() throws Exception {
        String message = "TestMessage";
        String hash = hashingService.generateHash(message, "HMAC-SHA256");

        assertNotNull(hash);
        assertFalse(hash.isEmpty());
    }

    /** ✅ Testet AES-CMAC Hash-Generierung */
    @Test
    void testGenerateAesCmac() throws Exception {
        String message = "TestMessage";
        String hash = hashingService.generateHash(message, "AES-CMAC");

        assertNotNull(hash);
        assertFalse(hash.isEmpty());
    }

    /** ✅ Testet Fehler bei unbekanntem Hash-Algorithmus */
    @Test
    void testGenerateHashInvalidAlgorithm() {
        Exception exception = assertThrows(NoSuchAlgorithmException.class, () -> {
            hashingService.generateHash("TestMessage", "INVALID-ALGO");
        });

        assertTrue(exception.getMessage().contains("Nicht unterstützter Hash-Algorithmus"));
    }

    /** ✅ Testet SHA-256 Hash-Verifikation */
    @Test
    void testVerifySHA256Hash() throws Exception {
        String message = "TestMessage";
        String hash = hashingService.generateHash(message, "SHA-256");

        assertTrue(hashingService.verifyHash(message, hash, "SHA-256"));
        assertFalse(hashingService.verifyHash("WrongMessage", hash, "SHA-256"));
    }

    /** ✅ Testet HMAC-SHA256 Hash-Verifikation */
    @Test
    void testVerifyHmacSHA256() throws Exception {
        String message = "TestMessage";
        String hash = hashingService.generateHash(message, "HMAC-SHA256");

        assertTrue(hashingService.verifyHash(message, hash, "HMAC-SHA256"));
        assertFalse(hashingService.verifyHash("WrongMessage", hash, "HMAC-SHA256"));
    }

    /** ✅ Testet AES-CMAC Hash-Verifikation */
    @Test
    void testVerifyAesCmac() throws Exception {
        String message = "TestMessage";
        String hash = hashingService.generateHash(message, "AES-CMAC");

        assertTrue(hashingService.verifyHash(message, hash, "AES-CMAC"));
        assertFalse(hashingService.verifyHash("WrongMessage", hash, "AES-CMAC"));
    }

    /** ✅ Testet Fehler bei Hash-Verifikation mit ungültigem Algorithmus */
    @Test
    void testVerifyHashInvalidAlgorithm() {
        Exception exception = assertThrows(NoSuchAlgorithmException.class, () -> {
            hashingService.verifyHash("TestMessage", "someHash", "INVALID-ALGO");
        });

        assertTrue(exception.getMessage().contains("Nicht unterstützter Hash-Algorithmus"));
    }

    /** ✅ Testet AES-CMAC mit ungültiger Schlüssellänge */
    @Test
    void testComputeAesCmacInvalidKeyLength() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            hashingService.computeAesCmac("TestMessage", new byte[10]); // 10 Byte ist ungültig!
        });

        assertTrue(exception.getMessage().contains("AES-CMAC benötigt einen Schlüssel mit 16, 24 oder 32 Byte"));
    }

}
