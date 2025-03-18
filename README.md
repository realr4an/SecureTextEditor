# Secure Text Editor

Ein sicherer Texteditor mit Verschlüsselungs- und Hashing-Funktionen für vertrauliche Dokumente. Dieses Projekt besteht aus einem **Frontend** (React) und einem **Backend** (Spring Boot) mit verschiedenen Kryptographie-Funktionen.

## 🌜 Funktionen

- **Sichere Textverarbeitung** mit Verschlüsselung (AES, ChaCha20, etc.).
- **Hashing-Funktionen** wie SHA-256 und SHA-3.
- **Benutzerfreundliche Oberfläche** für eine intuitive Nutzung.
- **REST-API** für kryptographische Operationen.
- **Unit-Tests & Integration-Tests** zur Sicherstellung der Sicherheit.

---

## 🚀 Installation & Starten

### 1️⃣ Voraussetzungen

- **Backend**: Java 17+ & Maven
- **Frontend**: Node.js 18+ & npm/yarn
- **Datenbank**: (Falls verwendet, z. B. PostgreSQL)

---

### 2️⃣ Backend starten (Spring Boot)

#### 📦 Installation

```bash
cd secure-texteditor-backend
mvn clean install
```

#### ▶️ Starten

```bash
mvn spring-boot:run
```

Das Backend läuft dann unter:

```
http://localhost:8080
```

#### 🛠 API-Dokumentation (Swagger)

Nach dem Start ist die **API-Dokumentation** unter folgender URL verfügbar:

```
http://localhost:8080/swagger-ui/index.html
```

---

### 3️⃣ Frontend starten (React)

#### 📦 Installation

```bash
cd secure-texteditor-frontend
npm install
```

#### ▶️ Starten

```bash
npm start
```

Das Frontend läuft dann unter:

```
http://localhost:3000
```

---

## 💑 Dokumentation

| Bereich  | Ort |
|----------|-----|
| Backend API | `/docs/api` oder [Swagger UI](http://localhost:8080/swagger-ui/index.html) |
| Code-Dokumentation | `/docs/code` (falls generiert mit Javadoc/Doxygen) |
| Architektur-Diagramme | `/docs/architecture` |
| Test Coverage | `target/site/jacoco/index.html` nach `mvn test` |

---

## 🛠 Tests ausführen

### ✅ Unit-Tests (Backend)

```bash
cd secure-texteditor-backend
mvn test
```

### 📊 Test Coverage mit **JaCoCo**

```bash
mvn clean test jacoco:report
```

Dann Coverage-Bericht ansehen:

```
target/site/jacoco/index.html
```

---

## 📌 API-Endpunkte

Die wichtigsten API-Routen für Kryptographie:

| Methode | Endpoint | Beschreibung |
|---------|---------|--------------|
| `POST`  | `/api/crypto/encrypt` | Verschlüsselt eine Nachricht |
| `POST`  | `/api/crypto/decrypt` | Entschlüsselt eine Nachricht |
| `POST`  | `/api/hashing/hash` | Erstellt einen Hash (SHA-256, SHA-3, etc.) |
| `POST`  | `/api/hashing/verify` | Überprüft einen Hash |

Weitere Details: Siehe [Swagger UI](http://localhost:8080/swagger-ui/index.html)

---

## 💡 Entwicklung & Beiträge

Falls du beitragen möchtest:

1. Forke das Repository 🍴
2. Erstelle einen neuen Branch: `feature/neue-funktion` 🌱
3. Implementiere deine Änderungen ✨
4. Erstelle einen Pull Request ✅

---

## 🔐 Sicherheitshinweise

- Nutze **sichere Schlüssel** & sichere Passwörter.
- Speichere keine Klartext-Passwörter.
- Vermeide das Hardcodieren von kryptographischen Schlüsseln.
- Überprüfe regelmäßig die Abhängigkeiten auf Sicherheitslücken.

---


### 📞 Kontakt

Falls du Fragen hast, erstelle ein [Issue](https://github.com/realr4an/secure-texteditor/issues) oder kontaktiere mich per E-Mail. 🚀

