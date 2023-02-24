use itertools::Itertools;

use crate::{
    key::{Key, MixinKey},
    word::{RotateWordLeft, RotateWordRight, Word},
};

/// Unfortunately, constant calculations in Rust
/// are not yet stable enough to accept only arrays
/// of the required length as input, so the trait-method
/// have to return an error
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The input data must be a multiple of the word bytes len
    WrongInputSize,
}

pub(crate) trait DecodeAsBlocks {
    /// This function splits `Self` into blocks (pair of words) and executes the RC5 encryption algorithm
    /// `Error` - if `&self` cannot be divided into blocks!
    fn decode_as_blocks<W: Word>(&self, key: impl Key, round_count: u8) -> Result<Vec<u8>, Error>;
}
impl<T: AsRef<[u8]>> DecodeAsBlocks for T {
    fn decode_as_blocks<W: Word>(&self, key: impl Key, round_count: u8) -> Result<Vec<u8>, Error> {
        process_blocks(self.as_ref(), |b| {
            rc5_decode(b, &key.mixin::<W>(round_count), round_count)
        })
    }
}

pub(crate) trait EncodeAsBlocks {
    /// This function splits `Self` into blocks (pair of words) and executes the RC5 decryption algorithm
    /// `Error` - if `&self` cannot be divided into blocks!
    fn encode_as_blocks<W: Word>(&self, key: impl Key, round_count: u8) -> Result<Vec<u8>, Error>;
}

impl<T: AsRef<[u8]>> EncodeAsBlocks for T {
    fn encode_as_blocks<W: Word>(&self, key: impl Key, round_count: u8) -> Result<Vec<u8>, Error> {
        process_blocks(self.as_ref(), |b| {
            rc5_encode(b, &key.mixin::<W>(round_count), round_count)
        })
    }
}

/// The function splits the input into words
/// and then into blocks and executes on
/// each `processor` closure
///
/// `Error` - cannot be divided into blocks!
fn process_blocks<W: Word>(
    input: &[u8],
    processor: impl Fn((W, W)) -> (W, W),
) -> Result<Vec<u8>, Error> {
    if input.len() % W::BYTES != 0 {
        return Err(Error::WrongInputSize);
    }

    input
        .chunks(W::BYTES)
        .map(W::from_le_bytes)
        .chunks(2)
        .into_iter()
        .map(|mut words| match words.next().zip(words.next()) {
            Some(block) => Ok(processor(block)),
            None => Err(Error::WrongInputSize),
        })
        .try_fold(Vec::with_capacity(input.len()), |mut result, block| {
            let block = block?;
            result.append(&mut block.0.into_le_bytes());
            result.append(&mut block.1.into_le_bytes());
            Ok(result)
        })
}

/// RC5 Encode Function
/// Check 4.1 in [the specification](https://www.grc.com/r&d/rc5.pdf).
fn rc5_encode<W: Word>(block: (W, W), key_table: &[W], round_count: u8) -> (W, W) {
    let (mut a, mut b) = block;

    a = a.wrapping_add(&key_table[0]);
    b = b.wrapping_add(&key_table[1]);
    for index in 1..=(round_count as usize) {
        a = a
            .bitxor(b)
            .rotate_word_left(b)
            .wrapping_add(&key_table[2 * index]);
        b = b
            .bitxor(a)
            .rotate_word_left(a)
            .wrapping_add(&key_table[2 * index + 1]);
    }
    (a, b)
}

/// RC5 Decode Function
/// Check 4.2 in [the specification](https://www.grc.com/r&d/rc5.pdf).
fn rc5_decode<W: Word>(block: (W, W), key_table: &[W], round_count: u8) -> (W, W) {
    let (mut a, mut b) = block;

    for index in (1..=round_count as usize).rev() {
        b = b
            .wrapping_sub(&key_table[2 * index + 1])
            .rotate_word_right(a)
            .bitxor(a);
        a = a
            .wrapping_sub(&key_table[2 * index])
            .rotate_word_right(b)
            .bitxor(b);
    }
    b = b.wrapping_sub(&key_table[1]);
    a = a.wrapping_sub(&key_table[0]);

    (a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        assert_eq!(
            rc5_encode((10u16, 10u16), &[0x00, 0x01, 0x02, 0x03], 1),
            (2050, 8231)
        );
    }

    #[test]
    fn test_decode() {
        assert_eq!(
            rc5_decode((2050u16, 8231), &[0x00, 0x01, 0x02, 0x03], 1),
            (10, 10)
        );
    }

    #[test]
    fn test_process_blocks() {
        assert_eq!(
            process_blocks(
                &[0xff, 0xf0, 0xff, 0xf0],
                |(w1, w2): (u8, u8)| -> (u8, u8) { (w2, w1) }
            )
            .unwrap(),
            [0xf0, 0xff, 0xf0, 0xff]
        );
    }
}
