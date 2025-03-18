package com.example.security;

import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * @class CryptoService
 * @brief Bietet Verschlüsselungs- und Entschlüsselungsfunktionen mit
 *        Unterstützung für verschiedene Algorithmen.
 */
public class CryptoService {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Eine Instanz von SecureRandom zur Erzeugung kryptographisch sicherer
     * Zufallswerte.
     */
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Logger-Instanz für die Protokollierung von Nachrichten in der
     * CryptoService-Klasse.
     */
    private static final Logger logger = Logger.getLogger(CryptoService.class.getName());

    /**
     * @brief Erstellt einen geheimen Schlüssel für die Verschlüsselung.
     * @param algorithm Der Verschlüsselungsalgorithmus (z. B. "AES" oder
     *                  "ChaCha20").
     * @param keySize   Die Schlüssellänge in Bits.
     * @param password  Falls vorhanden, ein Passwort zur Ableitung des Schlüssels.
     * @param salt      Falls ein Passwort genutzt wird, das dazugehörige Salt.
     * @return Der generierte SecretKey.
     * @throws Exception Falls die Schlüsselgenerierung fehlschlägt.
     */
    public SecretKey generateKey(String algorithm, int keySize, char[] password, byte[] salt) throws Exception {
        logger.info("Generating key for algorithm: " + algorithm);
        if (password != null && password.length > 0) {
            return generateKeyFromPassword(algorithm, password, keySize, salt);
        } else {
            return generateRandomKey(algorithm, keySize);
        }
    }

    /**
     * @brief Erzeugt einen Schlüssel aus einem Passwort mithilfe eines
     *        Key-Derivation-Algorithmus.
     * @param algorithm Der zu verwendende Algorithmus.
     * @param password  Das Passwort zur Schlüsselableitung.
     * @param keySize   Die gewünschte Schlüssellänge in Bits.
     * @param salt      Das Salt zur Erhöhung der Sicherheit.
     * @return Der generierte SecretKey.
     * @throws Exception Falls ein Fehler bei der Ableitung auftritt.
     */
    private SecretKey generateKeyFromPassword(String algorithm, char[] password, int keySize, byte[] salt)
            throws Exception {
        logger.info("Generating key from password for algorithm: " + algorithm);
        byte[] keyBytes;
        try {
            if ("AES".equals(algorithm) || "ChaCha20".equals(algorithm)) {
                keyBytes = SCrypt.generate(new String(password).getBytes(), salt, 16384, 8, 1, keySize / 8);
            } else if ("PBEWithSHA256".equals(algorithm)) {
                PBEKeySpec spec = new PBEKeySpec(password, salt, 65536, keySize);
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                keyBytes = factory.generateSecret(spec).getEncoded();
            } else {
                throw new IllegalArgumentException("Unbekannter PBE-Algorithmus: " + algorithm);
            }
        } finally {
            Arrays.fill(password, '\0');
            logger.info("Password securely cleared from memory.");
        }
        return new SecretKeySpec(keyBytes, algorithm);
    }

    /**
     * @brief Erstellt einen zufälligen Verschlüsselungsschlüssel.
     * @param algorithm Der zu verwendende Algorithmus.
     * @param keySize   Die gewünschte Schlüssellänge in Bits.
     * @return Der generierte SecretKey.
     * @throws Exception Falls ein Fehler auftritt.
     */
    private SecretKey generateRandomKey(String algorithm, int keySize) throws Exception {
        logger.info("Generating random key for algorithm: " + algorithm);
        byte[] keyBytes = new byte[keySize / 8];
        secureRandom.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, algorithm);
    }

    /**
     * @brief Verschlüsselt eine Nachricht mit dem angegebenen Algorithmus.
     * @param algorithm Verschlüsselungsalgorithmus.
     * @param mode      Verschlüsselungsmodus (z. B. "CBC", "GCM").
     * @param padding   Padding-Verfahren (z. B. "PKCS5Padding").
     * @param keyLength Schlüssellänge in Bits.
     * @param plaintext Die zu verschlüsselnde Nachricht.
     * @param password  Optionales Passwort für passwortbasierte Verschlüsselung
     *                  (PBE).
     * @return Ein Map-Objekt mit dem verschlüsselten Text, dem Schlüssel und den
     *         Metadaten.
     * @throws Exception Falls ein Fehler bei der Verschlüsselung auftritt.
     */
    public Map<String, String> encrypt(String algorithm, String mode, String padding, int keyLength, String plaintext,
            char[] password) throws Exception {
        logger.info(
                "🔒 Starting encryption process: Algorithm=" + algorithm + ", Mode=" + mode + ", Padding=" + padding);

        if (algorithm == null || algorithm.isEmpty()) {
            throw new IllegalArgumentException("Kein Algorithmus angegeben!");
        }

        SecretKey key;
        byte[] salt = null;
        byte[] iv = null;

        // Falls PBE verwendet wird (Passwort vorhanden)
        if (password != null && password.length > 0) {
            salt = new byte[16];
            secureRandom.nextBytes(salt);
            key = generateKeyFromPassword(algorithm, password, keyLength, salt);
            logger.info("🔑 Using password-based encryption (PBE).");

            // **⚠️ Spezialfälle: PBE benötigt evtl. IV!**
            if (("AES".equals(algorithm) && "CBC".equals(mode)) || "ChaCha20".equals(algorithm)) {
                iv = generateIV(algorithm, mode);
                logger.info("🔑 Generierte IV für PBE-Mode: " + algorithm + " / " + mode);
            }

            // **⚠️ AES-GCM mit PBE benötigt ebenfalls eine IV!**
            if ("AES".equals(algorithm) && "GCM".equals(mode)) {
                iv = generateIV(algorithm, mode);
                logger.info("🔑 Generierte IV für AES-GCM (PBE): " + Base64.getEncoder().encodeToString(iv));
            }
        }
        // Falls KEIN PBE → Generiere zufälligen Schlüssel & IV
        else {
            key = generateRandomKey(algorithm, keyLength);
            iv = generateIV(algorithm, mode);
            logger.info("🔑 Using random key encryption.");
        }

        // **Validiere IV für ChaCha20 oder AES-GCM**
        if (("ChaCha20".equals(algorithm) || "GCM".equals(mode)) && (iv == null || iv.length == 0)) {
            throw new IllegalArgumentException("❌ Kein IV für diesen Modus vorhanden!");
        }

        // Wähle die richtige ParameterSpec
        AlgorithmParameterSpec parameterSpec = getParameterSpec(algorithm, mode, salt, iv);

        // Dynamische Konstruktion des Cipher-Algorithmus-Strings
        String cipherAlgorithm = algorithm;
        if (!cipherAlgorithm.equals("ChaCha20")) {
            if (mode != null && !mode.equalsIgnoreCase("None")) {
                cipherAlgorithm += "/" + mode;
            }
            // if (padding != null && !padding.equalsIgnoreCase("NoPadding")) {
            cipherAlgorithm += "/" + padding;
            // }
        }

        // Cipher initialisieren & Verschlüsseln
        Cipher cipher = Cipher.getInstance(cipherAlgorithm, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());

        logger.info("✅ Encryption successful.");

        // MAC generieren
        Map<String, String> result = new HashMap<>();
        result.put("encrypted", Base64.getEncoder().encodeToString(encryptedBytes));
        result.put("key", Base64.getEncoder().encodeToString(key.getEncoded()));

        // Speichere Salt, falls PBE verwendet wurde
        if (password != null && password.length > 0) {
            result.put("salt", Base64.getEncoder().encodeToString(salt));
            logger.info("🔑 Stored Salt for PBE algorithm.");
        }

        // Speichere IV, falls verwendet
        if (iv != null) {
            result.put("iv", Base64.getEncoder().encodeToString(iv));
            logger.info("🔑 Stored IV for algorithm.");
        }

        // Passwort sicher löschen
        if (password != null) {
            Arrays.fill(password, '\0');
            logger.info("🔒 Passwort sicher aus Speicher gelöscht.");
        }
        logger.info("Encryption result: " + result);
        return result;
    }

    /**
     * @brief Entschlüsselt eine verschlüsselte Nachricht.
     * @param algorithm    Der Verschlüsselungsalgorithmus.
     * @param mode         Der Verschlüsselungsmodus.
     * @param padding      Das Padding-Verfahren.
     * @param keyLength    Die Schlüssellänge in Bits.
     * @param ciphertext   Der verschlüsselte Text.
     * @param ivBase64     Base64-kodierter Initialisierungsvektor (IV).
     * @param saltBase64   Base64-kodiertes Salt (falls PBE verwendet wird).
     * @param keyBase64    Base64-kodierter Schlüssel.
     * @param macAlgorithm Optionaler MAC-Algorithmus.
     * @param password     Optionales Passwort für passwortbasierte Entschlüsselung.
     * @return Der entschlüsselte Klartext.
     * @throws Exception Falls die Entschlüsselung fehlschlägt.
     */
    public String decrypt(String algorithm, String mode, String padding, int keyLength, String ciphertext,
            String ivBase64, String saltBase64, String keyBase64, String macAlgorithm,
            char[] password) throws Exception {
        logger.info("🔓 Starting decryption for Algorithm=" + algorithm + ", Mode=" + mode);

        if (algorithm == null || algorithm.isEmpty()) {
            throw new IllegalArgumentException("❌ Kein Algorithmus angegeben!");
        }

        byte[] salt = (saltBase64 != null && !saltBase64.isEmpty()) ? Base64.getDecoder().decode(saltBase64) : null;
        byte[] iv = (ivBase64 != null && !ivBase64.isEmpty()) ? Base64.getDecoder().decode(ivBase64) : null;
        byte[] keyBytes = (keyBase64 != null && !keyBase64.isEmpty()) ? Base64.getDecoder().decode(keyBase64) : null;
        SecretKey key;

        // Falls PBE aktiv ist (Passwort & Salt vorhanden)
        if (password != null && password.length > 0 && salt != null) {
            key = generateKeyFromPassword(algorithm, password, keyLength, salt);
            logger.info("🔑 PBE-Schlüssel erfolgreich generiert aus Passwort.");

            // **⚠️ Spezialfall: AES-CBC im PBE-Modus benötigt zusätzlich ein IV!**
            if ("AES".equals(algorithm) && "CBC".equals(mode) && iv == null) {
                throw new IllegalArgumentException("❌ Kein IV für AES-CBC mit PBE vorhanden!");
            }
        }
        // Falls KEIN PBE → Nutze gespeicherten Schlüssel
        else if (keyBytes != null) {
            key = new SecretKeySpec(keyBytes, algorithm);
            logger.info("🔑 Schlüssel erfolgreich aus JSON geladen.");

            // **IV ist für alle nicht-PBE Modi erforderlich**
            if (iv == null || iv.length == 0) {
                throw new IllegalArgumentException("❌ Kein IV vorhanden, aber für diesen Modus erforderlich!");
            }
        }
        // Falls kein Salt und kein Key → Fehler!
        else {
            throw new IllegalArgumentException("❌ Kein gültiger Schlüssel oder Salt gefunden!");
        }

        // AlgorithmParameterSpec setzen
        AlgorithmParameterSpec parameterSpec = getParameterSpec(algorithm, mode, salt, iv);

        // Cipher initialisieren
        Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/" + padding, "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

        // Entschlüsseln
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        String plaintext = new String(decryptedBytes);

        logger.info("✅ Decryption successful!");

        // Passwort sicher löschen
        if (password != null) {
            Arrays.fill(password, '\0');
            logger.info("🔒 Passwort sicher aus Speicher gelöscht.");
        }

        return plaintext;
    }

    private AlgorithmParameterSpec getParameterSpec(String algorithm, String mode, byte[] salt, byte[] iv) {
        if ("PBEWithSHA256And128BitAES-CBC-BC".equals(algorithm)) {
            if (salt == null) {
                throw new IllegalArgumentException("❌ Kein Salt für PBE gefunden!");
            }
            logger.info("🔑 Using PBEParameterSpec with salt.");
            return new PBEParameterSpec(salt, 65536);
        }

        if ("GCM".equals(mode)) {
            if (iv == null) {
                throw new IllegalArgumentException("❌ Kein IV für GCM-Modus vorhanden!");
            }
            logger.info("🔑 Using GCMParameterSpec with IV.");
            return new GCMParameterSpec(128, iv);
        }

        if (iv == null) {
            throw new IllegalArgumentException("❌ Kein IV für diesen Modus vorhanden!");
        }

        logger.info("🔑 Using IvParameterSpec with IV.");
        return new IvParameterSpec(iv);
    }

    private byte[] generateIV(String algorithm, String mode) {
        int ivSize = "ChaCha20".equals(algorithm) || "GCM".equals(mode) ? 12 : 16;
        byte[] iv = new byte[ivSize];
        secureRandom.nextBytes(iv);
        return iv;
    }

    /**
     * @brief Generiert einen MAC-Hash für eine Nachricht.
     * @param message      Die Nachricht.
     * @param key          Der geheime Schlüssel.
     * @param macAlgorithm Der gewünschte MAC-Algorithmus ("SHA-256",
     *                     "HMAC-SHA256").
     * @return Der Base64-kodierte MAC-Wert.
     * @throws Exception Falls der MAC-Algorithmus nicht unterstützt wird.
     */
    public String generateMAC(String message, SecretKey key, String macAlgorithm) throws Exception {
        if (macAlgorithm == null || macAlgorithm.isEmpty())
            return "";

        switch (macAlgorithm) {
            case "SHA-256":
                return Base64.getEncoder()
                        .encodeToString(MessageDigest.getInstance("SHA-256").digest(message.getBytes()));
            case "HMAC-SHA256":
                Mac hmac = Mac.getInstance("HmacSHA256");
                hmac.init(key);
                return Base64.getEncoder().encodeToString(hmac.doFinal(message.getBytes()));
            default:
                throw new IllegalArgumentException("Unbekannter MAC-Algorithmus: " + macAlgorithm);
        }
    }
}
