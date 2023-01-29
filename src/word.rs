use std::{fmt::Debug, ops::AddAssign};

use byterepr::ByteRepr;
use num_traits::{PrimInt, WrappingAdd, WrappingSub, Zero};

/// A trait presenter a word in RC5.
///
/// For more information, refer to section
/// two of [the specification](https://www.grc.com/r&d/rc5.pdf).
///
/// # Quote from the specification
///
/// RC5 is word-oriented: all of the basic computational operations
/// have `w`-bit  words as input and outputs. RC5 is a block cipher with two-rod input (plain-text)
/// block size and a two-word (cipher-text) output block size.
///
/// The nominal choice for `w` is 32 bites, for which RC5 has 64-bit plaintext and ciphertext
/// blocksizes. RC5 is well defined for any `w` > 0, although for simplicity it is proposed
/// here that only th values 16, 32 and 64 be "allowable".
///
/// # Note
/// As part of this crate, in addition to 16, 32 and 64, word sizes 8 and 128 were also implemented.
/// This trait is also easy to adapt to any word size, but then you will have to manually implement
/// all the operations that were presented here (for standard Rust types they are made immediately
pub trait Word:
    Debug
    + Copy
    + Zero
    + PrimInt
    + GetP
    + GetQ
    + AddAssign<Self>
    + From<u8>
    + ByteRepr
    + WrappingAdd
    + WrappingSub
{
    // Count of bits inside word
    // `u8` is here for simplicity. Potentially, in case of need,
    // it is possible to expand the word length above 256,
    // then you should expand the data type to usize
    const BITS: u8;
    // Count of bytes inside word
    const BYTES: usize = (Self::BITS / 8) as usize;
}

macro_rules! impl_word_size {
    ($t:ty) => {
        impl Word for $t {
            const BITS: u8 = Self::BITS as u8;
        }
    };
}
impl_word_size!(u8);
impl_word_size!(u16);
impl_word_size!(u32);
impl_word_size!(u64);
impl_word_size!(u128);

/// Magic Const `P`
/// `P_w = Odd(( e - 2 ) * 2 ^ w)`
/// where `e` is base of natural logarithms
/// and `w` is bit size of `Self`
pub trait GetP {
    const P: Self;
}
macro_rules! impl_p {
    ($t:ty, $p:literal) => {
        impl GetP for $t {
            const P: Self = $p;
        }
    };
}
impl_p!(u8, 0xb7);
impl_p!(u16, 0xb7e1);
impl_p!(u32, 0xb7e15163);
impl_p!(u64, 0xb7e151628aed2a6b);
impl_p!(u128, 0xb7e151628aed2a6abf7158809cf4f3c7);

/// Magic Const `Q`
/// `P_w = Odd(( ф - 2 ) * 2 ^ w)`
/// where `ф` is golden ratio
/// and `w` is bit size of `Self`
pub trait GetQ {
    const Q: Self;
}
macro_rules! impl_q {
    ($t:ty, $q:literal) => {
        impl GetQ for $t {
            const Q: Self = $q;
        }
    };
}
impl_q!(u8, 0x9f);
impl_q!(u16, 0x9e37);
impl_q!(u32, 0x9e3779b9);
impl_q!(u64, 0x9e3779b97f4a7c15);
impl_q!(u128, 0x9e3779b97f4a7c15f39cc0605cedc835);

/// Arithmetic progression module `2 ^ w` determined by the "magic constants"
/// `P_w` & `Q_w` provided here from [`GetP`] & [`GetQ`] traits
pub struct PresudoRandomKeySequenceIterator<T: Clone + WrappingAdd + GetP + GetQ> {
    next: T,
}

impl<T: Clone + WrappingAdd + GetP + GetQ> Default for PresudoRandomKeySequenceIterator<T> {
    fn default() -> Self {
        Self { next: T::P }
    }
}

impl<T: Clone + WrappingAdd + GetP + GetQ> Iterator for PresudoRandomKeySequenceIterator<T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next.clone();
        self.next = self.next.wrapping_add(&T::Q);
        Some(current)
    }
}

impl<W: Word> PresudoRandomKeySequenceIterator<W> {
    pub fn collect_for_rounds_count(rounds_count: u8) -> Vec<W> {
        PresudoRandomKeySequenceIterator::<W>::default()
            .take(2usize * (rounds_count as usize + 1usize))
            .collect()
    }
}

#[cfg(test)]
mod presudo_random_key_sequence_test {
    use super::{GetP, GetQ, PresudoRandomKeySequenceIterator};

    #[test]
    fn test_sequence_for_rounds() {
        for rounds_count in 0..u8::MAX {
            assert_eq!(
                PresudoRandomKeySequenceIterator::<u16>::collect_for_rounds_count(rounds_count)
                    .len(),
                (2 * (rounds_count as usize + 1))
            );
        }
    }

    #[test]
    fn test_start_of_sequence() {
        assert_eq!(
            PresudoRandomKeySequenceIterator::<u64>::default()
                .take(4)
                .collect::<Vec<_>>()
                .as_slice(),
            [
                u64::P,
                u64::P.wrapping_add(u64::Q),
                u64::P.wrapping_add(u64::Q).wrapping_add(u64::Q),
                u64::P
                    .wrapping_add(u64::Q)
                    .wrapping_add(u64::Q)
                    .wrapping_add(u64::Q),
            ]
            .as_slice(),
        );
    }

    #[test]
    fn test_first_values() {
        let actual = PresudoRandomKeySequenceIterator::<u64>::default()
            .take(2 * (255 + 1))
            .inspect(|v| eprintln!("{v}"))
            .collect::<Vec<_>>();
        assert_eq!(actual.as_slice(), include!("../.data/table64_512.data"));
    }
}

pub(crate) trait RotateWordLeft: Word {
    /// Shifts the bits to the left by a specified amount,
    /// `n` module `<Self as Word>::BITS`, wrapping the truncated
    /// bits to the beginning of the resulting integer.
    fn rotate_word_left(self, n: Self) -> Self {
        self.rotate_left(
            n.rem(<Self as From<u8>>::from(Self::BITS))
                .to_u32()
                .expect("Safe because `rem` of u8 before"),
        )
    }
}
impl<W: Word> RotateWordLeft for W {}

pub(crate) trait RotateWordRight: Word {
    /// Shifts the bits to the right by a specified amount,
    /// `n` module `<Self as Word>::BITS`, wrapping the truncated
    /// bits to the beginning of the resulting integer.
    fn rotate_word_right(self, n: Self) -> Self {
        self.rotate_right(
            n.rem(<Self as From<u8>>::from(Self::BITS))
                .to_u32()
                .expect("Safe because `rem` of u8 before"),
        )
    }
}
impl<W: Word> RotateWordRight for W {}

#[cfg(test)]
mod rotate_word {
    use super::{RotateWordLeft, RotateWordRight};

    #[test]
    fn test_rotate_left() {
        assert_eq!(1u64.rotate_word_left(1u64), 2u64);
        assert_eq!(2u64.rotate_word_left(1u64), 4u64);
        assert_eq!(1u64.rotate_word_left(u64::MAX), 2u64.pow(63));
    }

    #[test]
    fn test_rotate_right() {
        assert_eq!(2u64.rotate_word_right(1u64), 1u64);
        assert_eq!(2u64.rotate_word_right(1u64), 1u64);
        assert_eq!(u64::MAX.rotate_word_right(1), u64::MAX);
    }
}
