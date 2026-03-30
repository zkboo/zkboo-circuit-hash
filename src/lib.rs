// SPDX-License-Identifier: LGPL-3.0-or-later

//! Cryptographic hash fingerprints for [zkboo] circuits.

#![no_std]
mod backend;
mod functions;

pub use backend::CircuitHashingBackend;
pub use functions::hash_circuit;
