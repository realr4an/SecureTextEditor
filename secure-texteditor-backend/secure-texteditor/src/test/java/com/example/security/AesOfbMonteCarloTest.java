// package com.example.security;

// import static org.junit.jupiter.api.Assertions.assertEquals;
// import com.example.security.parsingClasses.AesOfbTestVector;
// import com.example.security.parsingClasses.RspParser;
// import org.junit.jupiter.api.BeforeAll;
// import org.junit.jupiter.api.Test;
// import javax.crypto.Cipher;
// import javax.crypto.SecretKey;
// import javax.crypto.spec.IvParameterSpec;
// import javax.crypto.spec.SecretKeySpec;
// import java.util.List;

// public class AesOfbMonteCarloTest {

//     private static final String TEST_VECTOR_FILE = "/Users/realr4an/Documents/secure-text-editor/secure-texteditor-backend/secure-texteditor/src/test/java/com/example/security/parsingClasses/OFBMCT256.rsp"; // Passe den Pfad an
//     private static List<AesOfbTestVector> testVectors;

//     @BeforeAll
//     static void setUp() throws Exception {
//         testVectors = RspParser.parseOFBMCTFile(TEST_VECTOR_FILE);
//     }

//     @Test
//     void testAesOfbMonteCarloEncryption() throws Exception {
//         for (AesOfbTestVector vector : testVectors) {
//             byte[] key = hexStringToByteArray(vector.keyHex);
//             byte[] iv = hexStringToByteArray(vector.ivHex);
//             byte[] plaintext = hexStringToByteArray(vector.plaintextHex);
//             byte[] expectedCiphertext = hexStringToByteArray(vector.ciphertextHex);

//             byte[] output = plaintext.clone();

//             for (int j = 0; j < 1000; j++) {
//                 if (j == 0) {
//                     output = encryptAesOfb(output, key, iv);
//                 } else {
//                     output = encryptAesOfb(output, key, null);
//                 }
//             }

//             assertEquals(bytesToHex(expectedCiphertext), bytesToHex(output),
//                     "AES-OFB MCT Encryption Test fehlgeschlagen für COUNT = " + vector.count);

//             key = updateKey(key, output);
//             iv = output.clone();
//         }
//     }

//     private byte[] encryptAesOfb(byte[] input, byte[] key, byte[] iv) throws Exception {
//         SecretKey secretKey = new SecretKeySpec(key, "AES");
//         Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
//         cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv != null ? iv : new byte[16]));
//         return cipher.doFinal(input);
//     }

//     private byte[] updateKey(byte[] key, byte[] lastCiphertext) {
//         for (int i = 0; i < key.length; i++) {
//             key[i] ^= lastCiphertext[i % lastCiphertext.length];
//         }
//         return key;
//     }

//     private static byte[] hexStringToByteArray(String hex) {
//         int len = hex.length();
//         byte[] data = new byte[len / 2];
//         for (int i = 0; i < len; i += 2) {
//             data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
//                     + Character.digit(hex.charAt(i + 1), 16));
//         }
//         return data;
//     }

//     private static String bytesToHex(byte[] bytes) {
//         StringBuilder hexString = new StringBuilder();
//         for (byte b : bytes) {
//             hexString.append(String.format("%02x", b));
//         }
//         return hexString.toString();
//     }
// }
