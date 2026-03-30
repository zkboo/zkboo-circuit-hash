// SPDX-License-Identifier: LGPL-3.0-or-later

//! Implementation of the circuit hashing backend for ZKBoo circuits.

use zkboo::{
    backend::{Backend, Frontend},
    crypto::Hasher,
    memory::{FlexibleMemoryManager, MemoryManager},
    word::{CompositeWord, Word, WordIdx},
};

#[repr(u8)]
#[non_exhaustive]
pub enum Opcode {
    Input,
    Alloc,
    Constant,
    FromLeWords,
    ToLeWords,
    Output,
    Not,
    BitXor,
    BitAnd,
    BitXorConst,
    BitAndConst,
    UnboundedShl,
    UnboundedShr,
    RotateLeft,
    RotateRight,
    ReverseBits,
    SwapBytes,
    Cast,
    Carry,
}

/// Hasher backend for ZKBoo circuits.
#[derive(Debug)]
pub struct CircuitHashingBackend<H: Hasher> {
    hasher: H,
    memory_manager: FlexibleMemoryManager<usize>,
}

impl<H: Hasher> CircuitHashingBackend<H> {
    pub fn new() -> Self {
        const VERSION: u8 = 0u8;
        let mut hasher = H::new();
        hasher.update(&[VERSION]);
        return Self {
            hasher,
            memory_manager: FlexibleMemoryManager::new(),
        };
    }

    /// Wraps this circuit hashing backend into a [Frontend].
    ///
    /// Alias of [Backend::into_frontend].
    pub fn into_circuit_hasher(self) -> Frontend<Self> {
        return self.into_frontend();
    }

    fn ingest_opcode(&mut self, opcode: Opcode) {
        self.hasher.update(&[opcode as u8]);
    }

    fn ingest_word_type<W: Word, const N: usize>(&mut self) {
        self.hasher.update(&[(W::WIDTH / 8) as u8]);
        self.hasher.update(&(N as u128).to_le_bytes());
    }

    fn ingest_word<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>) {
        word.to_le_bytes()
            .into_iter()
            .for_each(|bs| self.hasher.update(bs.as_ref()));
    }

    fn ingest_idx<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>) {
        idx.into_array()
            .into_iter()
            .for_each(|i| self.hasher.update(&(i as u128).to_le_bytes()));
    }

    fn ingest_bool(&mut self, value: bool) {
        self.hasher.update(&[value as u8]);
    }

    fn ingest_usize(&mut self, value: usize) {
        self.hasher.update(&(value as u128).to_le_bytes());
    }
}

impl<H: Hasher> Backend for CircuitHashingBackend<H> {
    type FinalizeArg = ();
    type FinalizeResult = H::Digest;

    fn finalize(mut self, _arg: Self::FinalizeArg) -> Self::FinalizeResult {
        return self.hasher.finalize();
    }

    fn input<W: Word, const N: usize>(&mut self, _word: CompositeWord<W, N>) -> WordIdx<W, N> {
        let (idx, _size) = self.memory_manager.alloc::<W, N>();
        self.ingest_opcode(Opcode::Input);
        self.ingest_word_type::<W, N>();
        return idx;
    }

    fn alloc<W: Word, const N: usize>(&mut self) -> WordIdx<W, N> {
        let (idx, _size) = self.memory_manager.alloc::<W, N>();
        self.ingest_opcode(Opcode::Alloc);
        self.ingest_word_type::<W, N>();
        return idx;
    }

    fn constant<W: Word, const N: usize>(&mut self, word: CompositeWord<W, N>, out: WordIdx<W, N>) {
        self.ingest_opcode(Opcode::Constant);
        self.ingest_word_type::<W, N>();
        self.ingest_word(word);
        self.ingest_idx(out);
    }

    fn from_le_words<W: Word, const N: usize>(
        &mut self,
        ins: [WordIdx<W, 1>; N],
        out: WordIdx<W, N>,
    ) {
        self.ingest_opcode(Opcode::FromLeWords);
        self.ingest_word_type::<W, N>();
        for idx in ins.into_iter() {
            self.ingest_idx(idx);
        }
        self.ingest_idx(out);
    }

    fn to_le_words<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        outs: [WordIdx<W, 1>; N],
    ) {
        self.ingest_opcode(Opcode::ToLeWords);
        self.ingest_word_type::<W, N>();
        self.ingest_idx(in_);
        for idx in outs.into_iter() {
            self.ingest_idx(idx);
        }
    }

    fn output<W: Word, const N: usize>(&mut self, out: WordIdx<W, N>) {
        self.ingest_opcode(Opcode::Output);
        self.ingest_word_type::<W, N>();
        self.ingest_idx(out);
    }

    fn increase_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>) {
        self.memory_manager.increase_refcount(idx);
    }

    fn decrease_refcount<W: Word, const N: usize>(&mut self, idx: WordIdx<W, N>) {
        self.memory_manager.decrease_refcount(idx);
    }

    fn not<W: Word, const N: usize>(&mut self, in_: WordIdx<W, N>, out: WordIdx<W, N>) {
        self.ingest_opcode(Opcode::Not);
        self.ingest_word_type::<W, N>();
        self.ingest_idx(in_);
        self.ingest_idx(out);
    }

    fn bitxor<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: WordIdx<W, N>,
        out: WordIdx<W, N>,
    ) {
        self.ingest_opcode(Opcode::BitXor);
        self.ingest_word_type::<W, N>();
        self.ingest_idx(inl);
        self.ingest_idx(inr);
        self.ingest_idx(out);
    }

    fn bitand<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: WordIdx<W, N>,
        out: WordIdx<W, N>,
    ) {
        self.ingest_opcode(Opcode::BitAnd);
        self.ingest_word_type::<W, N>();
        self.ingest_idx(inl);
        self.ingest_idx(inr);
        self.ingest_idx(out);
    }

    fn bitxor_const<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: CompositeWord<W, N>,
        out: WordIdx<W, N>,
    ) {
        self.ingest_opcode(Opcode::BitXorConst);
        self.ingest_word_type::<W, N>();
        self.ingest_idx(inl);
        self.ingest_word(inr);
        self.ingest_idx(out);
    }

    fn bitand_const<W: Word, const N: usize>(
        &mut self,
        inl: WordIdx<W, N>,
        inr: CompositeWord<W, N>,
        out: WordIdx<W, N>,
    ) {
        self.ingest_opcode(Opcode::BitAndConst);
        self.ingest_word_type::<W, N>();
        self.ingest_idx(inl);
        self.ingest_word(inr);
        self.ingest_idx(out);
    }

    fn unbounded_shl<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    ) {
        self.ingest_opcode(Opcode::UnboundedShl);
        self.ingest_word_type::<W, N>();
        self.ingest_idx(in_);
        self.ingest_usize(shift);
        self.ingest_idx(out);
    }

    fn unbounded_shr<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    ) {
        self.ingest_opcode(Opcode::UnboundedShr);
        self.ingest_word_type::<W, N>();
        self.ingest_idx(in_);
        self.ingest_usize(shift);
        self.ingest_idx(out);
    }

    fn rotate_left<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    ) {
        self.ingest_opcode(Opcode::RotateLeft);
        self.ingest_word_type::<W, N>();
        self.ingest_idx(in_);
        self.ingest_usize(shift);
        self.ingest_idx(out);
    }

    fn rotate_right<W: Word, const N: usize>(
        &mut self,
        in_: WordIdx<W, N>,
        shift: usize,
        out: WordIdx<W, N>,
    ) {
        self.ingest_opcode(Opcode::RotateRight);
        self.ingest_word_type::<W, N>();
        self.ingest_idx(in_);
        self.ingest_usize(shift);
        self.ingest_idx(out);
    }

    fn reverse_bits<W: Word, const N: usize>(&mut self, in_: WordIdx<W, N>, out: WordIdx<W, N>) {
        self.ingest_opcode(Opcode::ReverseBits);
        self.ingest_word_type::<W, N>();
        self.ingest_idx(in_);
        self.ingest_idx(out);
    }

    fn swap_bytes<W: Word, const N: usize>(&mut self, in_: WordIdx<W, N>, out: WordIdx<W, N>) {
        self.ingest_opcode(Opcode::SwapBytes);
        self.ingest_word_type::<W, N>();
        self.ingest_idx(in_);
        self.ingest_idx(out);
    }

    fn cast<W: Word, T: Word>(&mut self, in_: WordIdx<W, 1>, out: WordIdx<T, 1>) {
        self.ingest_opcode(Opcode::Cast);
        self.ingest_word_type::<W, 1>();
        self.ingest_word_type::<T, 1>();
        self.ingest_idx(in_);
        self.ingest_idx(out);
    }

    fn carry<W: Word, const N: usize>(
        &mut self,
        p: WordIdx<W, N>,
        g: WordIdx<W, N>,
        carry_in: bool,
        out: WordIdx<W, N>,
    ) {
        self.ingest_opcode(Opcode::Carry);
        self.ingest_word_type::<W, N>();
        self.ingest_idx(p);
        self.ingest_idx(g);
        self.ingest_bool(carry_in);
        self.ingest_idx(out);
    }
}
