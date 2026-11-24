//! Shared daemon state passed through Axum `State<Arc<AppState>>`.
//!
//! Replaces process-global `OnceLock<Mutex<...>>` singletons so the router
//! can be instantiated cleanly in parallel integration tests and avoids
//! lock-held copies and read-path disk I/O.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use axum::body::Bytes;
use tokio::sync::Semaphore;

pub(crate) struct StoredObject {
    pub data: Bytes,
    pub name: String,
}

type Store<T> = Mutex<(u64, BTreeMap<u64, T>)>;

pub(crate) struct AppState {
    objects: Store<StoredObject>,
    reports: Store<Arc<ntod_analysis::Report>>,
    captures: Store<Arc<Vec<ntod_capture::RawFrame>>>,
    streams: Store<Arc<AtomicBool>>,
    history: RwLock<ntod_analysis::history::History>,
    /// Bounds concurrent heavy uploads / remote captures.
    pub heavy_jobs: Arc<Semaphore>,
    #[cfg(feature = "ai")]
    pub ai: ntod_ai::Ollama,
}

impl AppState {
    pub fn new() -> Self {
        Self::with_data_dir(ntod_analysis::history::data_dir())
    }

    pub fn with_data_dir(dir: PathBuf) -> Self {
        Self {
            objects: Mutex::new((1, BTreeMap::new())),
            reports: Mutex::new((1, BTreeMap::new())),
            captures: Mutex::new((1, BTreeMap::new())),
            streams: Mutex::new((1, BTreeMap::new())),
            history: RwLock::new(ntod_analysis::history::History::open(&dir)),
            heavy_jobs: Arc::new(Semaphore::new(4)),
            #[cfg(feature = "ai")]
            ai: ntod_ai::Ollama::from_env(),
        }
    }

    /// Move carved bytes out of a report into the store and stamp ids —
    /// the report then carries download references, not payload.
    pub fn store_objects(&self, r: &mut ntod_analysis::Report) {
        if r.objects.is_empty() {
            return;
        }
        let Ok(mut s) = self.objects.lock() else {
            return;
        };
        for o in &mut r.objects {
            if o.data.is_empty() {
                continue;
            }
            let id = s.0;
            s.0 += 1;
            let ext: String = o
                .mime
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .take(16)
                .collect();
            let name = format!("carved-{id}.{}", if ext.is_empty() { "bin" } else { &ext });
            s.1.insert(
                id,
                StoredObject {
                    data: Bytes::from(std::mem::take(&mut o.data)),
                    name,
                },
            );
            o.id = Some(id);
        }
        while s.1.len() > 64 {
            let Some(&k) = s.1.keys().next() else { break };
            s.1.remove(&k);
        }
    }

    /// Zero-copy fetch of a carved object (`Bytes::clone` is an atomic refcount bump).
    pub fn get_object(&self, id: u64) -> Option<(Bytes, String)> {
        self.objects
            .lock()
            .ok()?
            .1
            .get(&id)
            .map(|o| (o.data.clone(), o.name.clone()))
    }

    pub fn store_report(&self, r: ntod_analysis::Report) -> (u64, Arc<ntod_analysis::Report>) {
        let mut s = match self.reports.lock() {
            Ok(s) => s,
            Err(e) => e.into_inner(),
        };
        let id = s.0;
        s.0 += 1;
        let arc = Arc::new(r);
        s.1.insert(id, arc.clone());
        while s.1.len() > 4 {
            let Some(&k) = s.1.keys().next() else { break };
            s.1.remove(&k);
        }
        (id, arc)
    }

    pub fn get_report(&self, id: u64) -> Option<Arc<ntod_analysis::Report>> {
        self.reports.lock().ok()?.1.get(&id).cloned()
    }

    pub fn store_capture(&self, frames: Vec<ntod_capture::RawFrame>) -> Option<u64> {
        if frames.is_empty() {
            return None;
        }
        let mut s = self.captures.lock().ok()?;
        let id = s.0;
        s.0 += 1;
        s.1.insert(id, Arc::new(frames));
        while s.1.len() > 2 {
            let Some(&k) = s.1.keys().next() else { break };
            s.1.remove(&k);
        }
        Some(id)
    }

    /// Clone the `Arc` under the lock and release immediately so export work
    /// never blocks concurrent uploads or exports.
    pub fn get_capture(&self, id: u64) -> Option<Arc<Vec<ntod_capture::RawFrame>>> {
        self.captures.lock().ok()?.1.get(&id).cloned()
    }

    /// Read-only device registry query — zero disk I/O.
    pub fn devices(&self) -> Vec<ntod_analysis::history::DevInfo> {
        self.history.read().map(|h| h.devices()).unwrap_or_default()
    }

    /// Read-only alert log query — zero disk I/O.
    pub fn alerts(&self) -> Vec<ntod_analysis::history::AlertRec> {
        self.history.read().map(|h| h.alerts()).unwrap_or_default()
    }

    /// Fold a finished *live* report into in-memory history and persist atomically.
    pub fn observe_history(
        &self,
        r: &ntod_analysis::Report,
    ) -> Vec<ntod_analysis::report::Finding> {
        let Ok(mut h) = self.history.write() else {
            return Vec::new();
        };
        let findings = h.observe(r, now_ms());
        let _ = h.save();
        findings
    }

    /// Fold a finished *live* report into history and append findings to `r`.
    pub fn history_observe(&self, r: &mut ntod_analysis::Report) {
        let findings = self.observe_history(r);
        r.findings.extend(findings);
    }

    // ---------- SSE cancel tokens ----------

    pub fn new_token(&self) -> u64 {
        let Ok(mut s) = self.streams.lock() else {
            return 0;
        };
        let tk = s.0;
        s.0 += 1;
        s.1.insert(tk, Arc::new(AtomicBool::new(false)));
        while s.1.len() > 64 {
            let Some(&k) = s.1.keys().next() else { break };
            if let Some(flag) = s.1.remove(&k) {
                flag.store(true, Ordering::Relaxed);
            }
        }
        tk
    }

    pub fn token_flag(&self, tk: u64) -> Arc<AtomicBool> {
        self.streams
            .lock()
            .ok()
            .and_then(|s| s.1.get(&tk).cloned())
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)))
    }

    pub fn cancel_token(&self, tk: u64) {
        if let Some(f) = self.streams.lock().ok().and_then(|s| s.1.get(&tk).cloned()) {
            f.store(true, Ordering::Relaxed);
        }
    }

    pub fn drop_token(&self, tk: u64) {
        if let Ok(mut s) = self.streams.lock() {
            s.1.remove(&tk);
        }
    }
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
