import { useState } from "react";
import { invoke } from "@tauri-apps/api/tauri";
import "./App.css";

function App() {
  const [apiKey, setApiKey] = useState("");
  const [status, setStatus] = useState("Warte auf Key...");
  const [isSaved, setIsSaved] = useState(false);

  async function saveKey() {
    if (!apiKey) return;
    setStatus("Verbinde...");
    try {
      // Sendet den Key an das Rust-Backend
      await invoke("set_api_key", { key: apiKey });
      setStatus("Aktiv & Überwache Logs");
      setIsSaved(true);
    } catch (e) {
      setStatus("Fehler: " + e);
    }
  }

  return (
    <div className="container">
      <h1>VRC Tracker</h1>
      
      <div className="card">
        {!isSaved ? (
          <>
            <p>Gib deinen persönlichen API-Key ein, den du vom Discord Bot erhalten hast.</p>
            <input
              id="greet-input"
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="Füge hier deinen Key ein..."
              type="password"
            />
            <button type="button" onClick={() => saveKey()}>
              Verbinden
            </button>
          </>
        ) : (
          <div className="success-mode">
            <div className="pulse"></div>
            <h2>System Aktiv</h2>
            <p>Deine VRChat Logs und VRCX Daten werden anonymisiert synchronisiert.</p>
            <p className="status-text">Status: {status}</p>
          </div>
        )}
      </div>

      <p className="footer">Build v0.1.0 • Secure Connection</p>
    </div>
  );
}

export default App;