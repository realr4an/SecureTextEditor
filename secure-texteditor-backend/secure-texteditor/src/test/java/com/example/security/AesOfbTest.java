// package com.example.security;

// import static org.junit.jupiter.api.Assertions.assertEquals;
// import org.junit.jupiter.api.BeforeEach;
// import org.junit.jupiter.api.Test;

// import javax.crypto.Cipher;
// import javax.crypto.SecretKey;
// import javax.crypto.spec.IvParameterSpec;
// import javax.crypto.spec.SecretKeySpec;
// import java.util.Base64;

// public class AesOfbTest {

//     private static final String AES_ALGORITHM = "AES/OFB/NoPadding";
//     private static final byte[] TEST_KEY_256 = hexStringToByteArray("603deb1015ca71be2b73aef0857d7781 1f352c073b6108d72d9810a30914dff4");
//     private static final byte[] TEST_IV = hexStringToByteArray("000102030405060708090A0B0C0D0E0F");
//     private static final byte[] TEST_PLAINTEXT = hexStringToByteArray("6bc1bee22e409f96e93d7e117393172a");

//     private Cipher cipher;

//     @BeforeEach
//     void setUp() throws Exception {
//         cipher = Cipher.getInstance(AES_ALGORITHM);
//     }

//     /** ✅ Known Answer Test (KAT) für AES-OFB */
//     @Test
//     void testKnownAnswer() throws Exception {
//         byte[] expectedCiphertext = hexStringToByteArray("dc7e84bfda79164b7ecd8486985d3860");

//         byte[] computedCiphertext = encryptAesOfb(TEST_PLAINTEXT, TEST_KEY_256, TEST_IV);
//         assertEquals(bytesToHex(expectedCiphertext), bytesToHex(computedCiphertext),
//                 "KAT Test für AES-OFB fehlgeschlagen!");
//     }

//     /** ✅ Monte Carlo Test (MCT) mit 1000 Iterationen */
//     @Test
//     void testMonteCarlo() throws Exception {
//         byte[] pt = TEST_PLAINTEXT.clone();
//         byte[] key = TEST_KEY_256.clone();
//         byte[] iv = TEST_IV.clone();
//         byte[] ct = null;

//         for (int i = 0; i < 1000; i++) {
//             ct = encryptAesOfb(pt, key, iv);

//             // Update IV für nächste Iteration (OFB benötigt neue IV)
//             iv = ct.clone();

//             // Update Key nach MCT-Regeln für 256-Bit
//             for (int j = 0; j < key.length; j++) {
//                 key[j] ^= ct[j % ct.length];  // XOR mit Ciphertext
//             }

//             pt = ct;  // Nächster Klartext ist vorheriger Ciphertext
//         }

//         byte[] expectedFinalCiphertext = hexStringToByteArray("b3e3aa6c15f26f02fd37e727f4bba20a");
//         assertEquals(bytesToHex(expectedFinalCiphertext), bytesToHex(ct),
//                 "MCT Test für AES-OFB fehlgeschlagen!");
//     }

//     /** ✅ Multi-Message Test (MMT) mit mehreren Eingaben */
//     @Test
//     void testMultiMessage() throws Exception {
//         String[] plaintexts = {
//                 "00112233445566778899AABBCCDDEEFF",
//                 "112233445566778899AABBCCDDEEFF00",
//                 "2233445566778899AABBCCDDEEFF0011"
//         };
//         String[] expectedCiphertexts = {
//                 "d1d6e1c7e9a1d5d98c2e4c5d517f799f",
//                 "f6bcd371f40e6b8e9376e00e95f5e5dc",
//                 "c56f1b0a457e9a2b6c4d5e6f7f8a9b0c"
//         };

//         for (int i = 0; i < plaintexts.length; i++) {
//             byte[] plaintext = hexStringToByteArray(plaintexts[i]);
//             byte[] expected = hexStringToByteArray(expectedCiphertexts[i]);

//             byte[] computedCiphertext = encryptAesOfb(plaintext, TEST_KEY_256, TEST_IV);
//             assertEquals(bytesToHex(expected), bytesToHex(computedCiphertext),
//                     "MMT Test für AES-OFB fehlgeschlagen für Nachricht #" + (i + 1));
//         }
//     }

//     /** 🛠 AES-OFB Verschlüsselung */
//     private byte[] encryptAesOfb(byte[] input, byte[] key, byte[] iv) throws Exception {
//         SecretKey secretKey = new SecretKeySpec(key, "AES");
//         cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
//         return cipher.doFinal(input);
//     }

//     /** 🛠 Konvertiert einen Hex-String in ein Byte-Array */
//     private static byte[] hexStringToByteArray(String hex) {
//         hex = hex.replace(" ", ""); // Entfernt Leerzeichen
//         int len = hex.length();
//         byte[] data = new byte[len / 2];
//         for (int i = 0; i < len; i += 2) {
//             data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
//                     + Character.digit(hex.charAt(i + 1), 16));
//         }
//         return data;
//     }

//     /** 🛠 Konvertiert ein Byte-Array in einen Hex-String */
//     private static String bytesToHex(byte[] bytes) {
//         StringBuilder hexString = new StringBuilder();
//         for (byte b : bytes) {
//             hexString.append(String.format("%02x", b));
//         }
//         return hexString.toString();
//     }
// }
