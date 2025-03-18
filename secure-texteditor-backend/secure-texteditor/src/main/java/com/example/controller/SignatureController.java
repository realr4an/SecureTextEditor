package com.example.controller;

import com.example.security.SignatureService;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * @class SignatureController
 * @brief REST-Controller zur Erstellung und Überprüfung digitaler Signaturen.
 *
 *        Dieser Controller stellt API-Endpunkte zur Signierung und zur
 *        Verifikation von Signaturen bereit.
 */
@RestController
@RequestMapping("/api/signature")
@CrossOrigin(origins = "http://localhost:3000")
public class SignatureController {

    private final SignatureService signatureService;
    private static final Logger logger = Logger.getLogger(SignatureController.class.getName());

    /**
     * @brief Konstruktor für den SignatureController.
     *
     *        Initialisiert eine neue Instanz von `SignatureService`.
     */
    public SignatureController() {
        this.signatureService = new SignatureService();
    }

    /**
     * @brief Erstellt eine digitale Signatur für den angegebenen Text.
     * 
     * @param request Ein JSON-Objekt mit den folgenden Parametern:
     *                - "text": Der zu signierende Text.
     *                - "algorithm": Das Signaturalgorithmus (z. B. "SHA256withDSA",
     *                "SHA256withECDSA").
     * 
     * @return Ein JSON-Objekt mit:
     *         - "signature": Die generierte Signatur (Base64-kodiert).
     *         - "error": Falls ein Fehler auftritt, eine Fehlermeldung.
     */
    @PostMapping("/sign")
    public Map<String, String> sign(@RequestBody Map<String, String> request) {
        Map<String, String> response = new HashMap<>();
        try {
            String text = request.get("text");
            String algorithm = request.get("algorithm");

            String signature = signatureService.signText(text, algorithm);
            response.put("signature", signature);
            logger.info("✅ Signierung erfolgreich!");

        } catch (Exception e) {
            response.put("error", "❌ Fehler beim Signieren: " + e.getMessage());
            logger.severe("❌ Fehler beim Signieren: " + e.getMessage());
        }
        return response;
    }

    /**
     * @brief Überprüft eine digitale Signatur für einen gegebenen Text.
     * 
     * @param request Ein JSON-Objekt mit den folgenden Parametern:
     *                - "text": Der ursprüngliche Klartext.
     *                - "algorithm": Das Signaturalgorithmus (z. B. "SHA256withDSA",
     *                "SHA256withECDSA").
     *                - "signature": Die zu überprüfende Signatur (Base64-kodiert).
     * 
     * @return Ein JSON-Objekt mit:
     *         - "isValid": `true`, wenn die Signatur gültig ist, sonst `false`.
     */
    @PostMapping("/verify")
    public Map<String, Boolean> verify(@RequestBody Map<String, String> request) {
        Map<String, Boolean> response = new HashMap<>();
        try {
            String text = request.get("text");
            String algorithm = request.get("algorithm");
            String signature = request.get("signature");

            boolean isValid = signatureService.verifySignature(text, algorithm, signature);
            response.put("isValid", isValid);

            if (isValid) {
                logger.info("✅ Signatur verifiziert!");
            } else {
                logger.warning("⚠️ Signatur ungültig! Manipulation möglich.");
            }

        } catch (Exception e) {
            response.put("isValid", false);
            logger.severe("❌ Fehler bei der Signaturprüfung: " + e.getMessage());
        }
        return response;
    }
}
