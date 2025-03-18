package com.example.security.parsingClasses;

import java.nio.file.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class RspParser {

    public static List<AesOfbTestVector> parseOFBMCTFile(String filePath) throws IOException {
        List<AesOfbTestVector> testVectors = new ArrayList<>();
        List<String> lines = Files.readAllLines(Paths.get(filePath));

        int count = -1;
        String keyHex = null;
        String ivHex = null;
        String ptHex = null;
        String ctHex = null;

        for (String line : lines) {
            line = line.trim();
            // Überspringe Kommentare oder leere Zeilen
            if (line.startsWith("#") || line.isEmpty()) {
                continue;
            }
            if (line.startsWith("[ENCRYPT]") || line.startsWith("[DECRYPT]")) {
                // Kann man auswerten, falls du beides hast
                continue;
            }

            // Parsen nach "COUNT = x", "KEY = hex", etc.
            if (line.startsWith("COUNT =")) {
                // Wenn wir schon einen Satz KEY/IV/PT/CT gesammelt hatten,
                // könnten wir ihn vorher hinzufügen. Hier aber einfacher:
                count = Integer.parseInt(line.split("=")[1].trim());
            } else if (line.startsWith("KEY =")) {
                keyHex = line.split("=")[1].trim();
            } else if (line.startsWith("IV =")) {
                ivHex = line.split("=")[1].trim();
            } else if (line.startsWith("PLAINTEXT =")) {
                ptHex = line.split("=")[1].trim();
            } else if (line.startsWith("CIPHERTEXT =")) {
                ctHex = line.split("=")[1].trim();
                // Jetzt haben wir alle 5 Felder, wir erstellen einen TestVector
                testVectors.add(new AesOfbTestVector(count, keyHex, ivHex, ptHex, ctHex));
                // Optional: zurücksetzen für nächsten Count
                keyHex = ivHex = ptHex = ctHex = null;
            }
        }
        return testVectors;
    }
}