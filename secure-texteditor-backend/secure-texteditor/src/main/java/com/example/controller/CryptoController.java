package com.example.controller;

import com.example.security.CryptoService;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * @class CryptoController
 * @brief REST-Controller für die Verschlüsselungs- und
 *        Entschlüsselungsfunktionen.
 * 
 *        Dieser Controller stellt Endpunkte für die API bereit, um Text mittels
 *        verschiedener
 *        Verschlüsselungsalgorithmen zu verschlüsseln und zu entschlüsseln.
 */
@RestController
@RequestMapping("/api/crypto")
@CrossOrigin(origins = "http://localhost:3000")
public class CryptoController {

    private final CryptoService cryptoService;
    private static final Logger logger = Logger.getLogger(CryptoController.class.getName());

    /**
     * @brief Konstruktor für den CryptoController.
     * @throws Exception Falls ein Fehler bei der Initialisierung des CryptoService
     *                   auftritt.
     */
    public CryptoController() throws Exception {
        this.cryptoService = new CryptoService();
    }

    /**
     * @brief Verschlüsselt einen übergebenen Text.
     * 
     * @param request Ein JSON-Objekt mit den folgenden Parametern:
     *                - "algorithm": Der Verschlüsselungsalgorithmus (z. B. AES,
     *                ChaCha20).
     *                - "mode": Der Modus der Verschlüsselung (z. B. CBC, GCM).
     *                - "padding": Das Padding-Verfahren (z. B. PKCS5Padding,
     *                NoPadding).
     *                - "text": Der zu verschlüsselnde Klartext.
     *                - "keyLength": Die Schlüssellänge in Bits (z. B. 128, 192,
     *                256).
     *                - "macAlgorithm": Falls vorhanden, der Hash-Algorithmus für
     *                die Integritätsprüfung.
     *                - "password": Falls passwortbasierte Verschlüsselung verwendet
     *                wird, das Passwort (Base64-kodiert).
     * 
     * @return Ein JSON-Objekt mit den Metadaten der Verschlüsselung:
     *         - "metadata": Die Metadaten der Verschlüsselung (Algorithmus, Modus,
     *         Padding, IV, Salt, etc.).
     *         - "keyData": Der generierte Schlüssel (falls nicht passwortbasiert).
     *         - "error": Falls ein Fehler auftritt, eine Fehlermeldung.
     */
    @PostMapping("/encrypt")
    public Map<String, Object> encrypt(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();
        char[] password = null;

        try {
            String algorithm = request.get("algorithm");
            String mode = request.get("mode");
            String padding = request.get("padding");
            String text = request.get("text");
            int keyLength = Integer.parseInt(request.get("keyLength"));
            String macAlgorithm = request.get("macAlgorithm");

            byte[] passwordBytes = request.get("password") != null ? Base64.getDecoder().decode(request.get("password"))
                    : null;
            if (passwordBytes != null) {
                password = new char[passwordBytes.length];
                for (int i = 0; i < passwordBytes.length; i++) {
                    password[i] = (char) passwordBytes[i];
                }
                Arrays.fill(passwordBytes, (byte) 0);
            }

            Map<String, String> encryptionResult = cryptoService.encrypt(
                    algorithm, mode, padding, keyLength, text, password);

            Map<String, String> metadataJson = new HashMap<>();
            metadataJson.put("algorithm", algorithm);
            metadataJson.put("mode", mode);
            metadataJson.put("padding", padding);
            metadataJson.put("keyLength", String.valueOf(keyLength));
            metadataJson.put("macAlgorithm", macAlgorithm);
            metadataJson.put("iv", encryptionResult.getOrDefault("iv", ""));
            metadataJson.put("salt", encryptionResult.getOrDefault("salt", ""));
            metadataJson.put("encrypted", encryptionResult.get("encrypted"));

            Map<String, String> keyJson = new HashMap<>();
            keyJson.put("key", encryptionResult.get("key"));

            response.put("metadata", metadataJson);
            response.put("keyData", keyJson);

            logger.info("✅ Encryption successful - Metadata & Key returned.");

        } catch (Exception e) {
            response.put("error", "Fehler beim Verschlüsseln: " + e.getMessage());
            logger.severe("❌ Encryption error: " + e.getMessage());
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
                logger.info("🔒 Passwort sicher aus Speicher gelöscht.");
            }
        }
        return response;
    }

    /**
     * @brief Entschlüsselt einen übergebenen verschlüsselten Text.
     * 
     * @param request Ein JSON-Objekt mit den folgenden Parametern:
     *                - "algorithm": Der verwendete Verschlüsselungsalgorithmus.
     *                - "mode": Der Modus der Verschlüsselung.
     *                - "padding": Das Padding-Verfahren.
     *                - "text": Der verschlüsselte Text.
     *                - "iv": Der Initialisierungsvektor (IV), falls erforderlich.
     *                - "salt": Das verwendete Salt, falls PBE verwendet wurde.
     *                - "key": Der verwendete Schlüssel (falls nicht
     *                passwortbasiert).
     *                - "macAlgorithm": Falls vorhanden, der Hash-Algorithmus für
     *                die Integritätsprüfung.
     *                - "password": Falls PBE verwendet wurde, das Passwort
     *                (Base64-kodiert).
     *                - "keyLength": Die Schlüssellänge.
     * 
     * @return Ein JSON-Objekt mit:
     *         - "decrypted": Der entschlüsselte Klartext.
     *         - "error": Falls ein Fehler auftritt, eine Fehlermeldung.
     */
    @PostMapping("/decrypt")
    public Map<String, String> decrypt(@RequestBody Map<String, String> request) {
        Map<String, String> response = new HashMap<>();
        char[] password = null;

        try {
            String algorithm = request.get("algorithm");
            String mode = request.get("mode");
            String padding = request.get("padding");
            String text = request.get("text");
            String iv = request.get("iv");
            String salt = request.get("salt");
            String key = request.get("key");
            String macAlgorithm = request.get("macAlgorithm");
            int keyLength = Integer.parseInt(request.get("keyLength"));

            byte[] passwordBytes = request.get("password") != null ? Base64.getDecoder().decode(request.get("password"))
                    : null;
            if (passwordBytes != null) {
                password = new char[passwordBytes.length];
                for (int i = 0; i < passwordBytes.length; i++) {
                    password[i] = (char) passwordBytes[i];
                }
                Arrays.fill(passwordBytes, (byte) 0);
            }

            String decryptedText = cryptoService.decrypt(
                    algorithm, mode, padding, keyLength, text, iv, salt, key, macAlgorithm, password);

            response.put("decrypted", decryptedText);
            logger.info("✅ Decryption successful.");

        } catch (Exception e) {
            response.put("error", "Fehler beim Entschlüsseln: " + e.getMessage());
            logger.severe("❌ Decryption error: " + e.getMessage());
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
                logger.info("🔒 Passwort sicher aus Speicher gelöscht.");
            }
        }
        return response;
    }

}
