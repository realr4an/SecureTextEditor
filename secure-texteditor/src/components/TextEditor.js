"use client";
import { useState, useEffect } from "react";

export default function TextEditor() {
  const [text, setText] = useState("");
  const [fileHandle, setFileHandle] = useState(null);
  const [fileName, setFileName] = useState("Neue Datei.txt");
  const [lastSavedText, setLastSavedText] = useState("");

  const [usePassword, setUsePassword] = useState(false);
  const [password, setPassword] = useState("");
  const [macAlgorithm, setMacAlgorithm] = useState("");
  const [algorithm, setAlgorithm] = useState("");
  const [mode, setMode] = useState("");
  const [padding, setPadding] = useState("");
  const [keyLength, setKeyLength] = useState(0);
  const [signatureAlgorithm, setSignatureAlgorithm] = useState("");

  const options = {
    standard: {
      AES: {
        modes: {
          CBC: { paddings: ["NoPadding", "PKCS5Padding", "PKCS7Padding", "ISO7816-4Padding", "ISO10126-2Padding", "X9.23Padding", "TBCPadding", "ZeroBytePadding"], keyLengths: [128, 192, 256] },
          GCM: { paddings: ["NoPadding"], keyLengths: [128, 192, 256] },
          CCM: { paddings: ["NoPadding"], keyLengths: [128, 192, 256] },
          CTR: { paddings: ["NoPadding"], keyLengths: [128, 192, 256] },
          OFB: { paddings: ["NoPadding", "PKCS5Padding", "PKCS7Padding", "ISO7816-4Padding", "ISO10126-2Padding", "X9.23Padding", "TBCPadding", "ZeroBytePadding"], keyLengths: [128, 192, 256] },
          CFB: { paddings: ["NoPadding", "PKCS5Padding", "PKCS7Padding", "ISO7816-4Padding", "ISO10126-2Padding", "X9.23Padding", "TBCPadding", "ZeroBytePadding"], keyLengths: [128, 192, 256] },
          CTS: { paddings: ["NoPadding"], keyLengths: [128, 192, 256] }
        }
      },
      ChaCha20: {
        modes: {
          None: { paddings: ["NoPadding"], keyLengths: [256] }
        }
      }
    },
    passwordBased: {
      AES: {
        modes: {
          CBC: { paddings: ["PKCS5Padding"], keyLengths: [128], pbeMode: ["PBEWithSHA256"] },
          GCM: { paddings: ["NoPadding"], keyLengths: [256], pbeMode: ["SCRYPT"] }
        }
      },
      ChaCha20: {
        modes: {
          None: { paddings: ["NoPadding"], keyLengths: [256], pbeMode: ["SCRYPT"] }
        }
      }
    }
  };

  const createNewFile = async () => {
    if (text !== lastSavedText) {
      const confirmSave = confirm("Es gibt ungespeicherte Änderungen. Möchtest du sie speichern?");
      if (confirmSave) {
        await saveFile();
      }
    }

    resetEditor();
  };

  const resetEditor = () => {
    setText("");
    setLastSavedText("");
    setFileHandle(null);
    setFileName("Neue Datei.txt");
    setUsePassword(false);
    setPassword("");
    setMacAlgorithm("");
    setAlgorithm("");
    setMode("");
    setPadding("");
    setKeyLength(0);
    setSignatureAlgorithm("");
  };

  const encodePasswordToBase64 = (password) => {
    return password ? btoa(unescape(encodeURIComponent(password))) : "";
  };

  const saveFileWithPicker = async (fileName, content, type) => {
    try {
      // 💡 Verhindert "SecurityError", indem sichergestellt wird, dass der Picker synchron geöffnet wird
      const fileHandle = await window.showSaveFilePicker({
        suggestedName: fileName,
        types: [{ description: "Dateien", accept: { [type]: [".txt", ".json"] } }]
      });

      const writable = await fileHandle.createWritable();
      await writable.write(content);
      await writable.close();

      console.log("✅ Datei erfolgreich gespeichert:", fileName);
    } catch (error) {
      if (error.name === "AbortError") {
        console.warn("⚠️ Benutzer hat den Speichervorgang abgebrochen.");
      } else {
        console.error("❌ Fehler beim Speichern:", error);
      }
    }
  };



  /** 📌 Datei öffnen */
  const openFile = async () => {
    try {
      // 📂 Öffne die verschlüsselte Datei (TXT)
      const [textHandle] = await window.showOpenFilePicker({
        types: [{ description: "Textdateien", accept: { "text/plain": [".txt"] } }]
      });

      const textFile = await textHandle.getFile();
      const fileText = await textFile.text();
      setFileHandle(textHandle);
      setFileName(textFile.name);

      // 📂 Öffne Metadaten-Datei (JSON)
      let metadata = null;
      alert("Bitte wähle die dazugehörige Metadaten-Datei (*.json) aus.");
      try {
        const [metaHandle] = await window.showOpenFilePicker({
          types: [{ description: "JSON-Dateien", accept: { "application/json": [".json"] } }]
        });

        const metaFile = await metaHandle.getFile();
        metadata = JSON.parse(await metaFile.text());
        console.log("✅ Metadaten geladen:", metadata);
      } catch (error) {
        console.warn("⚠️ Keine Metadaten-Datei gewählt. Datei wird als unverschlüsselt behandelt.");
      }

      // **🔍 Metadaten setzen**
      if (metadata) {
        setAlgorithm(metadata.algorithm || "");
        setMode(metadata.mode || "");
        setPadding(metadata.padding || "");
        setKeyLength(metadata.keyLength || 0);
        setMacAlgorithm(metadata.macAlgorithm || "");
        setSignatureAlgorithm(metadata.signatureAlgorithm || "");
      }

      // 🔍 **Falls Hash vorhanden ist → Verifizieren**
      if (metadata?.macAlgorithm && metadata?.mac) {
        console.log("🔍 Überprüfe Hash für Datei...");
        const verifyResponse = await fetch("http://localhost:8080/api/hashing/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: fileText, macAlgorithm: metadata.macAlgorithm, hash: metadata.mac }),
        });

        const verifyData = await verifyResponse.json();
        if (!verifyData.isValid) {
          alert("❌ Datei wurde möglicherweise manipuliert! Entschlüsselung wird abgebrochen.");
          return;
        } else {
          alert("✅ Datei ist unverändert!");
        }
      }

      // 🔏 **Falls digitale Signatur vorhanden → Verifizieren**
      if (metadata?.signatureAlgorithm && metadata?.signature) {
        console.log("🔏 Überprüfe digitale Signatur...");
        const verifySignatureResponse = await fetch("http://localhost:8080/api/signature/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            text: fileText,
            algorithm: metadata.signatureAlgorithm,
            signature: metadata.signature
          }),
        });

        const signatureData = await verifySignatureResponse.json();
        if (!signatureData.isValid) {
          alert("❌ Warnung: Digitale Signatur ist ungültig! Datei könnte manipuliert worden sein.");
        } else {
          console.log("✅ Digitale Signatur verifiziert!");
        }
      }

      // Falls Klartext → Direkt setzen
      if (!metadata || metadata.algorithm === "CLEAR_TEXT") {
        console.log("📜 Datei ist Klartext. Keine Entschlüsselung nötig.");
        setText(fileText);
        return;
      }

      // Falls verschlüsselt → Schlüssel abrufen
      let key = "";
      if (metadata.algorithm !== "CLEAR_TEXT") {
        alert("Falls die Datei verschlüsselt wurde, wähle die Schlüsseldatei (*.json) aus.");
        try {
          const [keyHandle] = await window.showOpenFilePicker({
            types: [{ description: "JSON-Dateien", accept: { "application/json": [".json"] } }]
          });

          const keyFile = await keyHandle.getFile();
          const keyData = JSON.parse(await keyFile.text());
          key = keyData.key || "";
          console.log("🔑 Schlüssel geladen.");
        } catch (keyError) {
          console.warn("⚠️ Keine Schlüssel-Datei gewählt.");
        }
      }

      let passwordToUse = "";
      if (metadata.salt) {
        passwordToUse = prompt("🔐 Datei wurde mit PBE verschlüsselt. Bitte gib das Passwort ein:");
        if (!passwordToUse) {
          alert("⚠️ Kein Passwort eingegeben. Entschlüsselung nicht möglich.");
          return;
        }
        passwordToUse = btoa(passwordToUse);
      }

      // 🔹 Entschlüsseln
      const response = await fetch("http://localhost:8080/api/crypto/decrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          algorithm: metadata.algorithm,
          mode: metadata.mode,
          padding: metadata.padding,
          keyLength: metadata.keyLength,
          text: fileText,
          iv: metadata.iv || "",
          salt: metadata.salt || "",
          key: key,
          macAlgorithm: metadata.macAlgorithm || "",
          password: passwordToUse
        }),
      });

      const data = await response.json();
      if (data.decrypted) {
        console.log("✅ Entschlüsselung erfolgreich!");
        setText(data.decrypted);
      } else {
        console.error("❌ Fehler beim Entschlüsseln:", data.error);
        alert("Fehler beim Entschlüsseln: " + data.error);
      }
    } catch (error) {
      console.error("❌ Fehler beim Öffnen der Datei:", error);
    }
  };





  /** 📌 Datei speichern */
  const saveFile = async () => {
    try {
      const fileNameInput = prompt("Bitte gib einen Namen für die Datei ein:", fileName.replace(".txt", ""));
      if (!fileNameInput) {
        alert("Speichern abgebrochen.");
        return;
      }

      const baseFileName = fileNameInput.trim();
      setFileName(`${baseFileName}.txt`);

      let metadata = {
        algorithm: algorithm || "CLEAR_TEXT",
        mode: mode || "",
        padding: padding || "",
        keyLength: algorithm ? parseInt(keyLength) : 0,
        macAlgorithm: macAlgorithm || "",
        signatureAlgorithm: signatureAlgorithm || "",
        iv: "",
        salt: "",
        mac: "",
        signature: ""
      };

      let encryptedText = text;
      let keyData = {}; // Falls Verschlüsselung aktiv, wird hier der Schlüssel gespeichert

      // 🔐 Falls Verschlüsselung aktiv → Verschlüsseln
      if (algorithm) {
        console.log("🔐 Verschlüssele Datei...");

        const encryptRequest = {
          algorithm,
          keyLength: parseInt(keyLength),
          text
        };

        if (algorithm !== "ChaCha20") {
          encryptRequest.mode = mode;
          encryptRequest.padding = padding;
        }

        if (usePassword) {
          encryptRequest.password = encodePasswordToBase64(password);
        }

        // console.log("📤 API-Anfrage für Verschlüsselung:", encryptRequest);

        const encryptResponse = await fetch("http://localhost:8080/api/crypto/encrypt", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(encryptRequest),
        });

        // ✅ Prüfen, ob Response erfolgreich ist
        if (!encryptResponse.ok) {
          console.error("❌ API-Fehler bei der Verschlüsselung:", encryptResponse.status, encryptResponse.statusText);
          alert("Fehler bei der Verschlüsselung: Server antwortet mit " + encryptResponse.status);
          return;
        }

        // ✅ JSON sicher auslesen
        let encryptData;
        try {
          encryptData = await encryptResponse.json();
        } catch (jsonError) {
          console.error("❌ Fehler beim Parsen der API-Antwort:", jsonError);
          alert("Fehler beim Parsen der API-Antwort. Ist die API online?");
          return;
        }

        if (!encryptData || !encryptData.metadata || !encryptData.metadata.encrypted) {
          console.error("❌ API-Antwort ungültig oder verschlüsselte Daten fehlen:", encryptData);
          alert("Fehler beim Verschlüsseln: Ungültige API-Antwort!");
          return;
        }

        // 🔑 Schlüssel & verschlüsselten Text speichern
        encryptedText = encryptData.metadata.encrypted; // Richtiges Feld verwenden
        keyData = encryptData.keyData || {}; // Schlüssel speichern

        // 📝 Metadaten korrekt setzen
        metadata.iv = encryptData.metadata.iv || "";
        metadata.salt = encryptData.metadata.salt || "";
        metadata.mode = encryptData.metadata.mode || "";
        metadata.padding = encryptData.metadata.padding || "";
        metadata.keyLength = encryptData.metadata.keyLength || 0;
        // metadata.macAlgorithm = encryptData.metadata.macAlgorithm || "";

        console.log("✅ Verschlüsselung erfolgreich. Erhaltene Daten:", encryptData);

      }

      // 🔍 Falls Hashing aktiv → Hash berechnen
      if (macAlgorithm) {
        console.log("🔍 Hashing für Datei...");

        const hashResponse = await fetch("http://localhost:8080/api/hashing/hash", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: encryptedText, macAlgorithm }),
        });

        const hashData = await hashResponse.json();
        console.log("📡 API-Antwort für Hashing:", hashData);

        if (!hashData.hashedText) {
          alert("Fehler beim Hashing!");
          return;
        }
        metadata.macAlgorithm = macAlgorithm;
        metadata.mac = hashData.hashedText;
      }

      // 🔏 Falls Signierung aktiv → Signatur erstellen
      if (signatureAlgorithm) {
        console.log("🔏 Signiere Datei...");

        const signResponse = await fetch("http://localhost:8080/api/signature/sign", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: encryptedText, algorithm: signatureAlgorithm }),
        });

        const signData = await signResponse.json();
        console.log("📡 API-Antwort für Signatur:", signData);

        if (!signData.signature) {
          alert("Fehler beim Signieren!");
          return;
        }

        metadata.signature = signData.signature;
      }

      // 📂 Speichern der Dateien
      await saveFileWithPicker(`${baseFileName}.txt`, encryptedText, "text/plain");
      await saveFileWithPicker(`${baseFileName}.json`, JSON.stringify(metadata, null, 2), "application/json");

      // 📂 Falls verschlüsselt → Schlüssel separat speichern
      if (algorithm) {
        await saveFileWithPicker(`${baseFileName}-key.json`, JSON.stringify(keyData, null, 2), "application/json");
      }

      alert("✅ Datei und Metadaten erfolgreich gespeichert!");
    } catch (error) {
      console.error("❌ Fehler beim Speichern:", error);
    }
  };

  /** 📌 Automatische Vorauswahl, falls nur eine Option existiert */
  useEffect(() => {
    if (algorithm) {
      const availableModes = Object.keys((usePassword ? options.passwordBased : options.standard)[algorithm]?.modes || {});
      if (availableModes.length === 1) setMode(availableModes[0]);
    }
  }, [algorithm, usePassword]);

  useEffect(() => {
    if (algorithm && mode) {
      const availablePaddings = (usePassword ? options.passwordBased : options.standard)[algorithm]?.modes[mode]?.paddings || [];
      if (availablePaddings.length === 1) setPadding(availablePaddings[0]);
    }
  }, [algorithm, mode, usePassword]);

  useEffect(() => {
    if (algorithm && mode && padding) {
      const availableKeyLengths = (usePassword ? options.passwordBased : options.standard)[algorithm]?.modes[mode]?.keyLengths || [];
      if (availableKeyLengths.length === 1) setKeyLength(availableKeyLengths[0]);
    }
  }, [algorithm, mode, padding, usePassword]);

  useEffect(() => {
    const availableHashAlgorithms = ["SHA-256", "AES-CMAC", "HMAC-SHA256"];
    if (availableHashAlgorithms.length === 1) setMacAlgorithm(availableHashAlgorithms[0]);
  }, []);

  useEffect(() => {
    const availableSignatures = ["SHA256withDSA", "SHA256withECDSA"];
    if (availableSignatures.length === 1) setSignatureAlgorithm(availableSignatures[0]);
  }, []);


  return (
    <div className="min-h-screen p-10 bg-gray-100 text-black transition-all">
      <div className="max-w-4xl mx-auto p-6 shadow-lg rounded-lg border bg-white transition-all">
        {/* Überschrift & Dateiname */}
        <div className="flex justify-between items-center mb-4">
          <h1 className="text-2xl font-bold">Sicherer Texteditor</h1>
          <span className="text-lg font-semibold text-gray-600">📝 {fileName}</span>
        </div>

        {/* Password-Based Encryption Switch */}
        <div className="flex items-center mb-4">
          <label className="mr-2 font-medium">🔐 Password-Based Encryption</label>
          <input type="checkbox" checked={usePassword} onChange={() => setUsePassword(!usePassword)} />
        </div>

        {/* Falls PBE aktiv ist, Passwort eingeben */}
        {usePassword && (
          <div className="flex flex-col mb-4">
            <label className="font-medium text-sm text-gray-700">Passwort</label>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
              className="p-2 border rounded bg-gray-100"
              placeholder="Gib dein Passwort ein..." />
          </div>
        )}

        {/* Auswahlbereich */}
        <div className="grid grid-cols-4 gap-4 mt-4">
          {/* Algorithmus Auswahl */}
          <div className="flex flex-col">
            <label className="font-medium text-sm text-gray-700">Algorithmus</label>
            <select value={algorithm} onChange={(e) => { setAlgorithm(e.target.value); setMode(""); setPadding(""); setKeyLength(""); }}
              className="p-2 border rounded bg-gray-100">
              <option value="">-- Wählen --</option>
              {usePassword
                ? Object.keys(options.passwordBased).map((alg) => (
                  <option key={alg} value={alg}>{alg}</option>
                ))
                : Object.keys(options.standard).map((alg) => (
                  <option key={alg} value={alg}>{alg}</option>
                ))
              }
            </select>
          </div>

          {/* Modus Auswahl (nur für AES, NICHT für ChaCha20) */}
          {algorithm && algorithm !== "ChaCha20" && (
            <div className="flex flex-col">
              <label className="font-medium text-sm text-gray-700">Modus</label>
              <select value={mode} onChange={(e) => { setMode(e.target.value); setPadding(""); setKeyLength(""); }}
                className="p-2 border rounded bg-gray-100">
                <option value="">-- Wählen --</option>
                {algorithm in (usePassword ? options.passwordBased : options.standard) &&
                  Object.keys((usePassword ? options.passwordBased : options.standard)[algorithm].modes).map((m) => (
                    <option key={m} value={m}>{m}</option>
                  ))
                }
              </select>
            </div>
          )}

          {/* Padding Auswahl (NUR für AES, NICHT für ChaCha20) */}
          {algorithm && algorithm !== "ChaCha20" && mode && (
            <div className="flex flex-col">
              <label className="font-medium text-sm text-gray-700">Padding</label>
              <select value={padding} onChange={(e) => { setPadding(e.target.value); setKeyLength(""); }}
                className="p-2 border rounded bg-gray-100">
                <option value="">-- Wählen --</option>
                {algorithm in (usePassword ? options.passwordBased : options.standard) &&
                  mode in (usePassword ? options.passwordBased : options.standard)[algorithm].modes &&
                  (usePassword ? options.passwordBased : options.standard)[algorithm].modes[mode].paddings.map((p) => (
                    <option key={p} value={p}>{p}</option>
                  ))
                }
              </select>
            </div>
          )}

          {/* Schlüssellänge Auswahl (ERSCHEINT DIREKT FÜR ChaCha20, sonst nach Padding) */}
          {algorithm && (algorithm === "ChaCha20" || padding) && (
            <div className="flex flex-col">
              <label className="font-medium text-sm text-gray-700">Schlüssellänge</label>
              <select value={keyLength} onChange={(e) => setKeyLength(e.target.value)}
                className="p-2 border rounded bg-gray-100">
                <option value="">-- Wählen --</option>
                {algorithm in (usePassword ? options.passwordBased : options.standard) &&
                  (algorithm === "ChaCha20"
                    ? options.passwordBased[algorithm].modes.None.keyLengths.map((k) => (
                      <option key={k} value={k}>{k}</option>
                    ))
                    : mode in (usePassword ? options.passwordBased : options.standard)[algorithm].modes &&
                    (usePassword ? options.passwordBased : options.standard)[algorithm].modes[mode].keyLengths.map((k) => (
                      <option key={k} value={k}>{k}</option>
                    ))
                  )}
              </select>
            </div>
          )}
        </div>

        {/* MAC Auswahl */}
        <div className="flex flex-col mt-4">
          <label className="font-medium text-sm text-gray-700">Hash/MAC</label>
          <select value={macAlgorithm} onChange={(e) => setMacAlgorithm(e.target.value)}
            className="p-2 border rounded bg-gray-100">
            <option value="">-- Kein Hash/MAC --</option>
            <option value="SHA-256">SHA-256</option>
            <option value="AES-CMAC">AES-CMAC</option>
            <option value="HMAC-SHA256">HMAC-SHA256</option>
          </select>
        </div>

        {/** 📌 Dropdown-Menü für Signaturalgorithmus */}
        <div className="flex flex-col mt-4">
          <label className="font-medium text-sm text-gray-700">Digitale Signatur</label>
          <select value={signatureAlgorithm} onChange={(e) => setSignatureAlgorithm(e.target.value)}
            className="p-2 border rounded bg-gray-100">
            <option value="">-- Keine Signatur --</option>
            <option value="SHA256withDSA">DSA (3072 Bit)</option>
            <option value="SHA256withECDSA">ECDSA (P-256)</option>
          </select>
        </div>

        {/* Textfeld */}
        <textarea value={text} onChange={(e) => setText(e.target.value)}
          className="w-full h-40 border p-2 rounded-lg mt-4 bg-gray-100"
          placeholder="Text hier eingeben..."
        />‚

        {/* Buttons */}
        <div className="flex space-x-2 mt-4">
          <button onClick={openFile} className="px-4 py-2 bg-green-500 text-white rounded">📂 Öffnen</button>
          <button onClick={saveFile} className="px-4 py-2 bg-blue-500 text-white rounded">💾 Speichern</button>
          <button onClick={createNewFile} className="px-4 py-2 bg-red-500 text-white rounded">🆕 Neue Datei</button>
        </div>
      </div>
    </div>
  );


}
