//! A real server in-process, on a local port, that tests can stop, restore
//! from a backup or replace with an empty one.
#![allow(dead_code, clippy::unwrap_used)]

use flectar_mail_sync_client::{Clock, Entry, MemoryStore, SyncClient};
use flectar_mail_sync_server::{Config, State, Store, serve};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub struct Server {
    pub url: String,
    address: SocketAddr,
    dir: tempfile::TempDir,
    database: PathBuf,
    state: Option<flectar_mail_sync_server::AppState>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl Server {
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    pub async fn start_with(adjust: impl Fn(&mut Config) + Send + 'static) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("sync.db");
        let mut server = Self {
            url: format!("http://{address}"),
            address,
            dir,
            database,
            state: None,
            stop: None,
            task: None,
        };
        server.run(listener, adjust);
        server
    }

    fn run(&mut self, listener: tokio::net::TcpListener, adjust: impl Fn(&mut Config)) {
        let store = Store::open(&self.database, 2).unwrap();
        let mut config = Config::new(self.url.clone());
        adjust(&mut config);
        let state = State::new(config, store);
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(serve(listener, state.clone(), async {
            let _ = stopped.await;
        }));
        self.state = Some(state);
        self.stop = Some(stop);
        self.task = Some(tokio::spawn(async move {
            task.await.unwrap().unwrap();
        }));
    }

    pub fn state(&self) -> &flectar_mail_sync_server::AppState {
        self.state.as_ref().unwrap()
    }

    /// A consistent copy of the database, to restore later.
    pub async fn backup(&self) -> PathBuf {
        let path = self.dir.path().join(format!("backup-{}.db", rand_suffix()));
        self.state().store.backup(path.clone()).await.unwrap();
        path
    }

    async fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop.send(()).unwrap();
        }
        if let Some(task) = self.task.take() {
            task.await.unwrap();
        }
        self.state = None;
    }

    /// Restart on the same address with the database at `from`, or with an
    /// empty one.
    pub async fn restart(&mut self, from: Option<&Path>) {
        self.stop().await;
        let database = self.dir.path().join(format!("sync-{}.db", rand_suffix()));
        if let Some(from) = from {
            std::fs::copy(from, &database).unwrap();
        }
        self.database = database;
        let listener = tokio::net::TcpListener::bind(self.address).await.unwrap();
        self.run(listener, |_| {});
    }
}

fn rand_suffix() -> String {
    let bytes: [u8; 8] = flectar_mail_sync_crypto::random_bytes().unwrap();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A device: its client and its store.
pub struct Device {
    pub client: SyncClient,
    pub store: MemoryStore,
}

impl Device {
    pub fn new(client: SyncClient) -> Self {
        Self {
            client,
            store: MemoryStore::default(),
        }
    }

    pub fn clock(&self) -> &Clock {
        self.client.clock()
    }

    pub fn set(&mut self, record_id: u8, value: &str) {
        let clock = std::sync::Arc::clone(self.client.clock());
        self.store
            .change(&clock, [record_id; 16], Some(pref(value)));
    }

    pub fn remove(&mut self, record_id: u8) {
        let clock = std::sync::Arc::clone(self.client.clock());
        self.store.change(&clock, [record_id; 16], None);
    }

    pub async fn sync(&mut self) -> flectar_mail_sync_client::SyncReport {
        self.client.sync(&mut self.store).await.unwrap()
    }

    pub fn value(&self, record_id: u8) -> Option<String> {
        self.store
            .entries
            .get(&[record_id; 16])
            .map(|entry| entry.body["value"].as_str().unwrap().to_owned())
    }
}

pub fn pref(value: &str) -> Entry {
    Entry {
        collection: "pref".into(),
        schema: 1,
        body: serde_json::json!({ "value": value }),
    }
}

pub fn http() -> reqwest::Client {
    reqwest::Client::new()
}
