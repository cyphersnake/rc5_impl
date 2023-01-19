use std::{fmt::Debug, ops::AddAssign};

use byterepr::ByteRepr;
use num_traits::{PrimInt, WrappingAdd, WrappingSub, Zero};

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
    const BITS: u8;
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
