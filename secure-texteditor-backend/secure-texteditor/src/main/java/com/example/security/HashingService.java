package com.example.security;

import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.engines.AESEngine;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * @class HashingService
 * @brief Bietet Funktionen zur Hash-Generierung und -Verifikation mit
 *        verschiedenen Algorithmen.
 */
public class HashingService {

    /**
     * Logger-Instanz für die Protokollierung von Nachrichten in der
     * CryptoService-Klasse.
     */
    private static final Logger logger = Logger.getLogger(HashingService.class.getName());

    // ✅ BouncyCastle als Standard-Provider aktivieren
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // **🔑 Statische Schlüssel für HMAC & CMAC (sichergestellt auf gültige
    // Längen)**
    private static final byte[] HMAC_SECRET_KEY = "SuperSecretHMACKey123".getBytes(); // Mindestens 16 Byte
    private static final byte[] AES_CMAC_SECRET_KEY = fixAesKeyLength("SuperSecretAESCMAC!".getBytes()); // 16, 24 oder
                                                                                                         // 32 Byte

    /**
     * @brief Generiert einen Hash basierend auf dem angegebenen Algorithmus.
     * @param message   Die Nachricht, die gehasht werden soll.
     * @param algorithm Der gewünschte Hash-Algorithmus ("SHA-256", "HMAC-SHA256",
     *                  "AES-CMAC").
     * @return Der Base64-kodierte Hash-Wert.
     * @throws Exception Falls der Algorithmus nicht unterstützt wird.
     */
    public String generateHash(String message, String algorithm) throws Exception {
        logger.info("🔍 Hashing mit Algorithmus (über BouncyCastle): " + algorithm);

        switch (algorithm) {
            case "SHA-256":
                return base64Encode(MessageDigest.getInstance("SHA-256", "BC").digest(message.getBytes()));

            case "HMAC-SHA256":
                return computeHmac(message, "HMac-SHA256", HMAC_SECRET_KEY);

            case "AES-CMAC":
                return computeAesCmac(message, AES_CMAC_SECRET_KEY);

            default:
                throw new NoSuchAlgorithmException("❌ Nicht unterstützter Hash-Algorithmus: " + algorithm);
        }
    }

    /**
     * @brief Berechnet einen HMAC-SHA256-Hash für eine Nachricht.
     * @param message       Die Nachricht, die gehasht werden soll.
     * @param hmacAlgorithm Der HMAC-Algorithmus ("HMac-SHA256").
     * @param keyBytes      Der geheime Schlüssel.
     * @return Der Base64-kodierte HMAC-Wert.
     * @throws Exception Falls ein Fehler beim Hashing auftritt.
     */
    // ✅ **HMAC-SHA256 mit stabilem Schlüssel**
    private String computeHmac(String message, String hmacAlgorithm, byte[] keyBytes) throws Exception {
        Mac mac = Mac.getInstance(hmacAlgorithm, "BC");
        SecretKey secretKey = new SecretKeySpec(keyBytes, hmacAlgorithm);
        mac.init(secretKey);
        return base64Encode(mac.doFinal(message.getBytes()));
    }

    /**
     * @brief Berechnet einen AES-CMAC-Hash für eine Nachricht.
     * @param message  Die Nachricht, die gehasht werden soll.
     * @param keyBytes Der geheime Schlüssel für AES-CMAC.
     * @return Der Base64-kodierte CMAC-Wert.
     * @throws Exception Falls ein ungültiger Schlüssel verwendet wird.
     */
    // ✅ **AES-CMAC mit korrektem Schlüssel (16, 24 oder 32 Byte)**
    public String computeAesCmac(String message, byte[] keyBytes) throws Exception {
        if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
            throw new IllegalArgumentException("❌ AES-CMAC benötigt einen Schlüssel mit 16, 24 oder 32 Byte!");
        }

        CMac cmac = new CMac(AESEngine.newInstance());
        cmac.init(new KeyParameter(keyBytes));

        byte[] messageBytes = message.getBytes();
        byte[] macResult = new byte[cmac.getMacSize()];

        cmac.update(messageBytes, 0, messageBytes.length);
        cmac.doFinal(macResult, 0);

        return base64Encode(macResult);
    }

    /**
     * @brief Stellt sicher, dass der AES-CMAC-Schlüssel eine gültige Länge hat (16,
     *        24 oder 32 Byte).
     * @param keyBytes Der ursprüngliche Schlüssel.
     * @return Der auf die richtige Länge angepasste Schlüssel.
     */
    // ✅ **Stellt sicher, dass der AES-CMAC-Schlüssel 16, 24 oder 32 Byte lang ist**
    private static byte[] fixAesKeyLength(byte[] keyBytes) {
        int length = keyBytes.length;
        if (length == 16 || length == 24 || length == 32) {
            return keyBytes; // Gültige Länge
        }

        byte[] fixedKey;
        if (length < 16) {
            fixedKey = new byte[16]; // Falls der Schlüssel zu kurz ist, auf 16 Byte aufstocken
        } else if (length < 24) {
            fixedKey = new byte[24];
        } else {
            fixedKey = new byte[32]; // Alles über 24 wird auf 32 verlängert
        }

        System.arraycopy(keyBytes, 0, fixedKey, 0, Math.min(keyBytes.length, fixedKey.length));
        return fixedKey;
    }

    /**
     * @brief Kodiert ein Byte-Array in Base64.
     * @param data Das zu kodierende Byte-Array.
     * @return Die Base64-kodierte Zeichenkette.
     */
    private String base64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * @brief Überprüft, ob ein gegebener Hash mit der berechneten Hash-Wert
     *        übereinstimmt.
     * @param message      Die Originalnachricht.
     * @param expectedHash Der erwartete Hash-Wert.
     * @param algorithm    Der verwendete Hash-Algorithmus ("SHA-256",
     *                     "HMAC-SHA256", "AES-CMAC").
     * @return True, wenn der Hash gültig ist, andernfalls false.
     * @throws Exception Falls der Algorithmus nicht unterstützt wird.
     */
    // ✅ **📌 Hash-Verifikation für SHA-256, HMAC-SHA256 & AES-CMAC**
    public boolean verifyHash(String message, String expectedHash, String algorithm) throws Exception {
        logger.info("🔍 Überprüfung des Hash mit Algorithmus: " + algorithm);

        String computedHash;
        switch (algorithm) {
            case "SHA-256":
                computedHash = base64Encode(MessageDigest.getInstance("SHA-256", "BC").digest(message.getBytes()));
                break;
            case "HMAC-SHA256":
                computedHash = computeHmac(message, "HMac-SHA256", HMAC_SECRET_KEY);
                break;
            case "AES-CMAC":
                computedHash = computeAesCmac(message, AES_CMAC_SECRET_KEY);
                break;
            default:
                throw new NoSuchAlgorithmException("❌ Nicht unterstützter Hash-Algorithmus: " + algorithm);
        }

        boolean isValid = computedHash.equals(expectedHash);
        if (isValid) {
            logger.info("✅ Hash erfolgreich verifiziert!");
        } else {
            logger.warning("⚠️ Hash-Verifikation fehlgeschlagen! Manipulation möglich.");
        }
        return isValid;
    }
}
