// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of circuit hashing functions for ZKBoo circuits.

use crate::CircuitHashingBackend;
use zkboo::{circuit::Circuit, crypto::Hasher};

/// Produces a circuit hash based on all public circuit information.
///
/// Note: Information about word type and width is ingested as part of hash generation,
///       but the specific values of input words are not, so that the circuit used for proof
///       generation and the circuit used for proof verification have the same hash.
pub fn hash_circuit<C: Circuit, H: Hasher>(circuit: &C) -> H::Digest {
    let mut circuit_hasher = CircuitHashingBackend::<H>::new().into_circuit_hasher();
    circuit.exec(&mut circuit_hasher);
    return circuit_hasher.finalize();
}
