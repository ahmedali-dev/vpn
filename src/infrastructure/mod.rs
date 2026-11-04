//! Technical services and external adapters.
//!
//! These modules handle operating-system networking, external processes, storage and encryption.

pub mod cores;
pub mod cryptography;
pub(crate) mod hostname;
pub mod logging;
pub mod mongo_library;
pub mod network;
pub mod persistence;
pub mod privileges;
pub mod transport;
