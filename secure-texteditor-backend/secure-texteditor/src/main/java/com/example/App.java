package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Hauptklasse der Spring Boot-Anwendung.
 * Diese Klasse startet den Webserver und die Anwendung.
 */
@SpringBootApplication
public class App {
    /**
     * Startmethode der Anwendung.
     *
     * @param args Kommandozeilenargumente
     */
    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
