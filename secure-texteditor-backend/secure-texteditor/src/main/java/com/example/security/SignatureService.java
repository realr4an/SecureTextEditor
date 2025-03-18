package com.example.security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * @class SignatureService
 * @brief Bietet Funktionen zum Erstellen und Verifizieren digitaler Signaturen.
 */
public class SignatureService {
    /**
     * Logger-Instanz für die Protokollierung von Nachrichten in der
     * SignatureService-Klasse.
     */
    private static final Logger logger = Logger.getLogger(SignatureService.class.getName());

    /**
     * Dateiname für den gespeicherten DSA-Schlüsselpaar.
     */
    private static final String DSA_KEY_FILE = "dsa_keypair.pem";

    /**
     * Dateiname für den gespeicherten ECDSA-Schlüsselpaar.
     */
    private static final String ECDSA_KEY_FILE = "ecdsa_keypair.pem";

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * @brief Erstellt eine digitale Signatur für den gegebenen Text.
     * @param text      Der zu signierende Text.
     * @param algorithm Der Signaturalgorithmus (SHA256withDSA oder
     *                  SHA256withECDSA).
     * @return Base64-kodierte Signatur.
     * @throws Exception Falls ein Fehler beim Signieren auftritt.
     */
    public String signText(String text, String algorithm) throws Exception {
        KeyPair keyPair = getKeyPair(algorithm);
        Signature signature = Signature.getInstance(algorithm, "BC");
        signature.initSign(keyPair.getPrivate());
        signature.update(text.getBytes());
        byte[] signedData = signature.sign();
        return Base64.getEncoder().encodeToString(signedData);
    }

    /**
     * @brief Verifiziert eine digitale Signatur.
     * @param text            Der ursprüngliche Text.
     * @param algorithm       Der Signaturalgorithmus (SHA256withDSA oder
     *                        SHA256withECDSA).
     * @param signatureBase64 Die Base64-kodierte Signatur.
     * @return True, wenn die Signatur gültig ist, sonst false.
     * @throws Exception Falls ein Fehler bei der Verifikation auftritt.
     */
    public boolean verifySignature(String text, String algorithm, String signatureBase64) throws Exception {
        KeyPair keyPair = getKeyPair(algorithm);
        Signature signature = Signature.getInstance(algorithm, "BC");
        signature.initVerify(keyPair.getPublic());
        signature.update(text.getBytes());
        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
        return signature.verify(signatureBytes);
    }

    /**
     * @brief Holt das gespeicherte Schlüsselpaar oder erstellt es, falls nicht
     *        vorhanden.
     * @param algorithm Der Signaturalgorithmus (SHA256withDSA oder
     *                  SHA256withECDSA).
     * @return Ein `KeyPair` mit dem gespeicherten oder neu generierten
     *         Schlüsselpaar.
     * @throws Exception Falls ein Fehler auftritt.
     */
    private KeyPair getKeyPair(String algorithm) throws Exception {
        String keyFile = algorithm.equals("SHA256withDSA") ? DSA_KEY_FILE : ECDSA_KEY_FILE;

        // 🔍 Prüfen, ob Schlüssel bereits existieren
        File file = new File(keyFile);
        if (file.exists()) {
            return loadKeyPair(keyFile, algorithm);
        }

        // 🔑 Falls nicht vorhanden, KeyPair generieren und speichern
        KeyPair keyPair = generateKeyPair(algorithm);
        saveKeyPair(keyPair, keyFile);
        return keyPair;
    }

    /**
     * @brief Erstellt ein neues Schlüsselpaar für das angegebene
     *        Signaturalgorithmus.
     * @param algorithm Der Signaturalgorithmus (SHA256withDSA oder
     *                  SHA256withECDSA).
     * @return Ein generiertes `KeyPair`.
     * @throws Exception Falls der Algorithmus nicht unterstützt wird.
     */
    private KeyPair generateKeyPair(String algorithm) throws Exception {
        KeyPairGenerator keyGen;
        if ("SHA256withDSA".equals(algorithm)) {
            keyGen = KeyPairGenerator.getInstance("DSA", "BC");
            keyGen.initialize(3072);
        } else if ("SHA256withECDSA".equals(algorithm)) {
            keyGen = KeyPairGenerator.getInstance("EC", "BC");
            keyGen.initialize(new ECGenParameterSpec("P-256"));
        } else {
            throw new IllegalArgumentException("❌ Nicht unterstützter Algorithmus: " + algorithm);
        }
        return keyGen.generateKeyPair();
    }

    /**
     * @brief Speichert das generierte Schlüsselpaar in einer Datei.
     * @param keyPair  Das zu speichernde `KeyPair`.
     * @param fileName Der Name der Datei, in die das Schlüsselpaar gespeichert
     *                 wird.
     * @throws Exception Falls ein Fehler beim Speichern auftritt.
     */
    private void saveKeyPair(KeyPair keyPair, String fileName) throws Exception {
        String privateKeyEncoded = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        String publicKeyEncoded = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

        try (PrintWriter out = new PrintWriter(new FileWriter(fileName))) {
            out.println(privateKeyEncoded);
            out.println(publicKeyEncoded);
        }

        logger.info("🔑 KeyPair gespeichert: " + fileName);
    }

    /**
     * @brief Lädt ein gespeichertes Schlüsselpaar aus einer Datei.
     * @param fileName  Der Name der Datei mit den gespeicherten Schlüsseln.
     * @param algorithm Der Signaturalgorithmus (SHA256withDSA oder
     *                  SHA256withECDSA).
     * @return Das wiederhergestellte `KeyPair`.
     * @throws Exception Falls der Algorithmus nicht unterstützt wird oder ein
     *                   Fehler beim Laden auftritt.
     */
    private KeyPair loadKeyPair(String fileName, String algorithm) throws Exception {
        try (BufferedReader reader = new BufferedReader(new FileReader(fileName))) {
            String privateKeyEncoded = reader.readLine();
            String publicKeyEncoded = reader.readLine();

            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyEncoded);
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyEncoded);

            KeyFactory keyFactory;
            if ("SHA256withDSA".equals(algorithm)) {
                keyFactory = KeyFactory.getInstance("DSA", "BC");
            } else if ("SHA256withECDSA".equals(algorithm)) {
                keyFactory = KeyFactory.getInstance("EC", "BC");
            } else {
                throw new IllegalArgumentException("❌ Nicht unterstützter Algorithmus: " + algorithm);
            }

            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            logger.info("🔑 KeyPair erfolgreich geladen aus: " + fileName);
            return new KeyPair(publicKey, privateKey);
        }
    }
}
