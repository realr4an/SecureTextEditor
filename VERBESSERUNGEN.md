# Verbesserungen und offene Punkte

Dieses Dokument sammelt Vorschläge für Verbesserungen im Projekt **Secure Text Editor**. Besonderes Augenmerk liegt auf Sicherheitsthemen.

## Bisher implementierte Funktionen

- Verschlüsselung mit unterschiedlichen Algorithmen (z.B. AES und ChaCha20)
- Hashing-Mechanismen inklusive SHA-256, HMAC und AES‑CMAC
- Signaturerzeugung mit DSA/ECDSA
- REST‑API für Kryptofunktionen
- Erste Unit-Tests für die wichtigsten Klassen

## Mögliche Verbesserungen

1. **Abhängigkeiten aktualisieren**
   - Regelmäßige Updates für BouncyCastle, Spring Boot und React/Next.js
   - Prüfen, ob verworfene Bibliotheken entfernt werden können

2. **Dokumentation erweitern**
   - Beispielanfragen für die REST‑API (Curl oder HTTPie)
   - Klare Anleitung zum Einrichten lokaler Entwicklungsumgebungen

3. **Tests ausbauen**
   - Zusätzliche Integrationstests für API‑Endpunkte
   - Automatisierte Tests für das Frontend

## Sicherheitshinweise und offene Security‑Issues

- **Fest kodierte Geheimschlüssel** in `HashingService.java` (`HMAC_SECRET_KEY` und `AES_CMAC_SECRET_KEY`). Diese sollten extern verwaltet und nicht im Repository abgelegt werden.
- **Beispiel-Schlüsseldateien** (`dsa_keypair.pem`, `ecdsa_keypair.pem`) befinden sich im Repository. Produktionsschlüssel dürfen hier niemals abgelegt werden.
- **Build-Artefakte und .DS_Store-Dateien** sind mit eingecheckt (Ordner `target` und diverse `.DS_Store`). Diese sollten aus dem Versionskontrollsystem entfernt und in `.gitignore` aufgenommen werden.
- Der `TextEditorController` nutzt `JFileChooser`. Bei einem Serverbetrieb ist das problematisch, da hier Eingaben auf Serverseite mögliche Sicherheitsrisiken bergen. Besser wäre ein dateibasiertes API ohne GUI-Komponenten.
- Prüfen, ob CORS-Konfigurationen ausreichend restriktiv sind (aktuell `@CrossOrigin(origins = "http://localhost:3000")`).

## Ausblick

- Zusätzliche Verschlüsselungsverfahren könnten ergänzt werden.
- DevOps-Anbindung (CI/CD) inklusive automatischer Security-Scans.
- Review der Repository-Struktur: Nur Quellcode und notwendige Ressourcen sollten versioniert sein.
