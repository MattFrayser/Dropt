use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::{watch, Mutex};

use crate::{server::session::Session, transfer::storage::ChunkStorage};

// State of Single file being Received
pub struct FileReceiveState {
    pub storage: ChunkStorage,
    pub total_chunks: usize,
    pub nonce: String,
    pub relative_path: String,
    pub file_size: u64,
}

// Distinguish between two Main modes.
// DashMaps are used for concurrent access
#[derive(Clone)]
pub enum TransferStorage {
    Send(Arc<DashMap<usize, Arc<std::fs::File>>>),
    // Receives DashMap holds an Arc<Mutex>> to be able to clone the file state
    // and drop the dashmap lock immediatly. This helps with concurrent proccess
    // competeing and waiting for dashmap
    Receive(Arc<DashMap<String, Arc<Mutex<FileReceiveState>>>>),
}

#[derive(Clone)]
pub struct AppState {
    pub session: Session,
    pub progress_sender: watch::Sender<f64>,
    pub transfers: TransferStorage,
}
impl AppState {
    pub fn new_send(session: Session, progress_sender: watch::Sender<f64>) -> Self {
        Self {
            session,
            progress_sender,
            transfers: TransferStorage::Send(Arc::new(DashMap::new())),
        }
    }

    pub fn new_receive(session: Session, progress_sender: watch::Sender<f64>) -> Self {
        Self {
            session,
            progress_sender,
            transfers: TransferStorage::Receive(Arc::new(DashMap::new())),
        }
    }

    //-- Helper Functions for safe access
    // helper functions return options since send or receive can call them
    // but different outcomes are needed, ie send doesnt have File stats to
    // keep track of so None is returned

    pub fn file_handles(&self) -> Option<&Arc<DashMap<usize, Arc<std::fs::File>>>> {
        match &self.transfers {
            TransferStorage::Send(handles) => Some(handles),
            _ => None,
        }
    }

    pub fn receive_sessions(&self) -> Option<&Arc<DashMap<String, Arc<Mutex<FileReceiveState>>>>> {
        match &self.transfers {
            TransferStorage::Receive(sessions) => Some(sessions),
            _ => None,
        }
    }

    pub fn transfer_count(&self) -> usize {
        match &self.transfers {
            TransferStorage::Send(sessions) => sessions.len(),
            TransferStorage::Receive(sessions) => sessions.len(),
        }
    }
}
