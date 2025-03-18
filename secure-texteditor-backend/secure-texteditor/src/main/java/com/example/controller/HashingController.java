package com.example.controller;

import com.example.security.HashingService;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * @class HashingController
 * @brief REST-Controller zur Berechnung und Überprüfung von Hash-Werten.
 * 
 *        Dieser Controller stellt API-Endpunkte zum Hashen von Texten und zur
 *        Überprüfung von Hash-Werten bereit.
 */
@RestController
@RequestMapping("/api/hashing")
@CrossOrigin(origins = "http://localhost:3000")
public class HashingController {

    private final HashingService hashingService;
    private static final Logger logger = Logger.getLogger(HashingController.class.getName());

    /**
     * @brief Konstruktor für den HashingController.
     * 
     *        Initialisiert eine neue Instanz von `HashingService`.
     */
    public HashingController() {
        this.hashingService = new HashingService();
    }

    /**
     * @brief Erstellt einen Hash-Wert für den gegebenen Text.
     * 
     * @param request Ein JSON-Objekt mit den folgenden Parametern:
     *                - "text": Der zu hashende Text.
     *                - "macAlgorithm": Der Hash-Algorithmus (z. B. "SHA-256",
     *                "HMAC-SHA256", "AES-CMAC").
     * 
     * @return Ein JSON-Objekt mit:
     *         - "hashedText": Der berechnete Hash-Wert (Base64-kodiert).
     *         - "error": Falls ein Fehler auftritt, eine Fehlermeldung.
     */
    @PostMapping("/hash")
    public Map<String, String> hash(@RequestBody Map<String, String> request) {
        Map<String, String> response = new HashMap<>();

        try {
            String text = request.get("text");
            String macAlgorithm = request.get("macAlgorithm");

            if (macAlgorithm == null || macAlgorithm.isEmpty()) {
                throw new IllegalArgumentException("Kein Hash-Algorithmus gewählt!");
            }

            String hashedText = hashingService.generateHash(text, macAlgorithm);
            response.put("hashedText", hashedText);
            logger.info("✅ Hashing erfolgreich!");

        } catch (Exception e) {
            response.put("error", "❌ Fehler beim Hashing: " + e.getMessage());
            logger.severe("Hashing error: " + e.getMessage());
        }

        return response;
    }

    /**
     * @brief Überprüft, ob ein gegebener Hash-Wert mit dem berechneten Hash
     *        übereinstimmt.
     * 
     * @param request Ein JSON-Objekt mit den folgenden Parametern:
     *                - "text": Der ursprüngliche Klartext.
     *                - "macAlgorithm": Der verwendete Hash-Algorithmus.
     *                - "hash": Der erwartete Hash-Wert (Base64-kodiert).
     * 
     * @return Ein JSON-Objekt mit:
     *         - "isValid": `true`, wenn der Hash-Wert gültig ist, sonst `false`.
     */
    @PostMapping("/verify")
    public Map<String, Boolean> verifyHash(@RequestBody Map<String, String> request) {
        Map<String, Boolean> response = new HashMap<>();

        try {
            String text = request.get("text");
            String macAlgorithm = request.get("macAlgorithm");
            String expectedHash = request.get("hash");

            boolean isValid = hashingService.verifyHash(text, expectedHash, macAlgorithm);
            response.put("isValid", isValid);

            if (isValid) {
                logger.info("✅ Hash verifiziert!");
            } else {
                logger.warning("⚠️ Hash stimmt nicht überein!");
            }

        } catch (Exception e) {
            response.put("isValid", false);
            logger.severe("❌ Fehler beim Hash-Verify: " + e.getMessage());
        }

        return response;
    }
}
