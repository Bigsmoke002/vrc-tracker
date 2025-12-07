#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use lazy_static::lazy_static;
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use regex::Regex;
use reqwest::Client;
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{Manager, State};

lazy_static! {
    static ref LOG_PATTERN: Regex = Regex::new(r"(\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2}) Log        -  \[(.*?)\] (.*)").unwrap();
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct LogPayload {
    hash: String,
    timestamp: String,
    #[serde(rename = "type")]
    log_type: String,
    world_id: Option<String>,
    data: serde_json::Value,
}

struct AppState {
    api_key: Mutex<String>,
    local_db_path: PathBuf,
}

// ACHTUNG: Hier deine Server-IP anpassen!
const API_URL: &str = "http://192.168.1.104:3000/api/logs";

fn init_local_db(path: &Path) -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open(path)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS sent_hashes (
            hash TEXT PRIMARY KEY,
            sent_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;
    Ok(conn)
}

fn hash_entry(timestamp: &str, log_type: &str, data_str: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(timestamp);
    hasher.update(log_type);
    hasher.update(data_str);
    format!("{:x}", hasher.finalize())
}

fn is_hash_sent(conn: &Connection, hash: &str) -> bool {
    let mut stmt = conn.prepare("SELECT 1 FROM sent_hashes WHERE hash = ?").unwrap();
    stmt.exists(params![hash]).unwrap_or(false)
}

fn mark_hash_sent(conn: &Connection, hash: &str) {
    let _ = conn.execute("INSERT OR IGNORE INTO sent_hashes (hash) VALUES (?)", params![hash]);
}

fn get_vrc_paths() -> (PathBuf, PathBuf) {
    let home = dirs::home_dir().unwrap();
    let appdata = home.join("AppData").join("LocalLow").join("VRChat").join("VRChat");
    let roaming = home.join("AppData").join("Roaming").join("VRCX");
    (appdata, roaming.join("VRCX.sqlite"))
}

async fn send_batch(client: &Client, api_key: &str, logs: Vec<LogPayload>) {
    if logs.is_empty() { return; }
    
    let res = client.post(API_URL)
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&logs)
        .send()
        .await;

    match res {
        Ok(r) => {
            if !r.status().is_success() {
                println!("Error sending logs: {:?}", r.status());
            }
        },
        Err(e) => println!("Network error: {:?}", e),
    }
}

fn parse_line(line: &str) -> Option<LogPayload> {
    if let Some(caps) = LOG_PATTERN.captures(line) {
        let ts_raw = caps.get(1)?.as_str();
        let log_type = "Generic"; 
        let content = caps.get(3)?.as_str();

        let timestamp = ts_raw.replace(".", "-").replace(" ", "T") + "Z";
        
        let hash = hash_entry(&timestamp, log_type, content);
        
        return Some(LogPayload {
            hash,
            timestamp,
            log_type: log_type.to_string(),
            world_id: None, 
            data: serde_json::json!({ "raw": content }),
        });
    }
    None
}

// FIX: Trennung von DB-Zugriff (Synchron) und Netzwerk (Asynchron)
async fn process_vrcx(vrcx_path: PathBuf, local_db_path: PathBuf, api_key: String) {
    if !vrcx_path.exists() { return; }

    // Block 1: Daten synchron auslesen und Verbindung sofort wieder schließen
    let batch = {
        let conn_res = Connection::open_with_flags(&vrcx_path, OpenFlags::SQLITE_OPEN_READ_ONLY);
        if conn_res.is_err() { return; }
        let vrcx_conn = conn_res.unwrap();
        let local_conn = init_local_db(&local_db_path).unwrap();

        let mut stmt = vrcx_conn.prepare("SELECT created_at, type, data, world_id FROM gamelog ORDER BY created_at DESC LIMIT 5000").unwrap();
        
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        }).unwrap();

        let mut temp_batch = Vec::new();

        for row in rows {
            if let Ok((ts, l_type, data, w_id)) = row {
                let hash = hash_entry(&ts, &l_type, &data);
                
                if !is_hash_sent(&local_conn, &hash) {
                    let payload = LogPayload {
                        hash: hash.clone(),
                        timestamp: ts,
                        log_type: l_type,
                        world_id: Some(w_id),
                        data: serde_json::from_str(&data).unwrap_or(serde_json::json!({})),
                    };
                    temp_batch.push(payload);
                    mark_hash_sent(&local_conn, &hash);
                }
            }
        }
        temp_batch 
    }; // HIER werden vrcx_conn und local_conn zerstört/gedroppt.

    // Block 2: Jetzt sicher asynchron senden
    if !batch.is_empty() {
        let client = Client::new();
        send_batch(&client, &api_key, batch).await;
    }
}

#[tauri::command]
fn set_api_key(key: String, state: State<AppState>) -> String {
    let mut db = state.api_key.lock().unwrap();
    *db = key.clone();
    
    let path = state.local_db_path.clone();
    
    // Starte den Hintergrundprozess
    tauri::async_runtime::spawn(async move {
        let (_log_dir, vrcx_path) = get_vrc_paths();
        process_vrcx(vrcx_path, path, key).await;
    });

    "Key saved".to_string()
}

fn start_watcher(api_key_store: Arc<Mutex<String>>, local_db_path: PathBuf) {
    thread::spawn(move || {
        let (log_dir, _) = get_vrc_paths();
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(tx, Config::default()).unwrap();
        
        if let Err(_) = watcher.watch(&log_dir, RecursiveMode::NonRecursive) {
            return;
        }

        for res in rx {
            match res {
                Ok(event) => {
                    if event.kind.is_modify() {
                        for path in event.paths {
                            if let Some(ext) = path.extension() {
                                if ext == "txt" {
                                    let content = fs::read_to_string(&path).unwrap_or_default();
                                    let lines: Vec<&str> = content.lines().rev().take(20).collect();
                                    
                                    let key = api_key_store.lock().unwrap().clone();
                                    if key.is_empty() { continue; }

                                    let conn = init_local_db(&local_db_path).unwrap();
                                    let client = Client::new();
                                    
                                    let mut batch = Vec::new();
                                    for line in lines {
                                        if let Some(payload) = parse_line(line) {
                                            if !is_hash_sent(&conn, &payload.hash) {
                                                mark_hash_sent(&conn, &payload.hash);
                                                batch.push(payload);
                                            }
                                        }
                                    }

                                    if !batch.is_empty() {
                                        let k = key.clone();
                                        tauri::async_runtime::spawn(async move {
                                            send_batch(&client, &k, batch).await;
                                        });
                                    }
                                }
                            }
                        }
                    }
                },
                Err(_) => {},
            }
        }
    });
}

fn main() {
    let app_data_dir = dirs::data_dir().unwrap().join("vrc-tracker");
    fs::create_dir_all(&app_data_dir).unwrap();
    let db_path = app_data_dir.join("tracker.db");

    let api_key_store = Arc::new(Mutex::new(String::new()));
    start_watcher(api_key_store.clone(), db_path.clone());

    tauri::Builder::default()
        .manage(AppState {
            api_key: Mutex::new(String::new()), 
            local_db_path: db_path,
        })
        .invoke_handler(tauri::generate_handler![set_api_key])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}