package com.example.controller;

import org.springframework.web.bind.annotation.*;
import javax.swing.*;
import java.io.*;

/**
 * @class TextEditorController
 * @brief Bietet API-Endpunkte für das Laden und Speichern von Dateien über
 *        einen nativen Datei-Dialog.
 *
 *        Diese Klasse nutzt die Java Swing `JFileChooser`, um dem Benutzer das
 *        Speichern und Öffnen von Dateien zu ermöglichen.
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:3000")
public class TextEditorController {

    /**
     * @brief Öffnet einen nativen Datei-Dialog, um eine Datei zu speichern.
     *
     *        Diese Methode ruft den JFileChooser auf, damit der Benutzer eine Datei
     *        speichern kann.
     *
     * @param content Der zu speichernde Textinhalt.
     * @return Eine Nachricht über das Ergebnis des Speichervorgangs:
     *         - `"Datei gespeichert: [Pfad]"`, falls erfolgreich.
     *         - `"Fehler: [Fehlermeldung]"`, falls ein Fehler auftritt.
     *         - `"Speichern abgebrochen."`, falls der Benutzer den Vorgang
     *         abbricht.
     */
    /** 📌 Öffnet einen nativen Datei-Dialog für das Speichern */
    @PostMapping("/save-dialog")
    public String saveWithDialog(@RequestBody String content) {
        JFileChooser fileChooser = new JFileChooser();
        int option = fileChooser.showSaveDialog(null);
        if (option == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
                writer.write(content);
                return "Datei gespeichert: " + file.getAbsolutePath();
            } catch (IOException e) {
                return "Fehler: " + e.getMessage();
            }
        }
        return "Speichern abgebrochen.";
    }

    /**
     * @brief Öffnet einen nativen Datei-Dialog, um eine Datei zu laden.
     *
     *        Diese Methode ermöglicht es dem Benutzer, eine Datei auszuwählen und
     *        ihren Inhalt zurückzugeben.
     *
     * @return Der Inhalt der geladenen Datei oder eine Fehlermeldung:
     *         - Der Dateiinhalt als `String`, falls erfolgreich.
     *         - `"Fehler: [Fehlermeldung]"`, falls ein Fehler auftritt.
     *         - `"Öffnen abgebrochen."`, falls der Benutzer den Vorgang abbricht.
     */
    /** 📌 Öffnet einen nativen Datei-Dialog für das Laden */
    @GetMapping("/open-dialog")
    public String openWithDialog() {
        JFileChooser fileChooser = new JFileChooser();
        int option = fileChooser.showOpenDialog(null);
        if (option == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                StringBuilder content = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line).append("\n");
                }
                return content.toString();
            } catch (IOException e) {
                return "Fehler: " + e.getMessage();
            }
        }
        return "Öffnen abgebrochen.";
    }
}
