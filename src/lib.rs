use std::{error, fmt};

#[cfg(feature = "secrecy")]
pub use secrecy;

mod key;
pub use key::Key;

mod word;
pub use word::Word;

mod block;
use block::{DecodeAsBlocks, EncodeAsBlocks};

mod settings;
pub use settings::{DefaultWord, Rc5Settings};

#[derive(Debug, PartialEq, Eq)]
/// Unfortunately, constant calculations in Rust
/// are not yet stable enough to accept only arrays
/// of the required length as input, so the trait-method
/// have to return an error
pub enum Error {
    /// The input data must be a multiple of the word bytes len
    WrongInputSize,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl error::Error for Error {}

impl From<block::Error> for Error {
    fn from(value: block::Error) -> Self {
        match value {
            block::Error::WrongInputSize => Error::WrongInputSize,
        }
    }
}

pub trait EncodeRc5 {
    /// Encode by RC5 with custom settings
    ///
    /// Check 4.1 in [the specification](https://www.grc.com/r&d/rc5.pdf).
    /// This function splits `Self` into blocks
    /// (pair of words) and executes the RC5 encryption algorithm
    /// `Error` - if `&self` cannot be divided into blocks!
    fn encode_rc5_with_settings<W: Word>(
        &self,
        key: impl Key,
        settings: Rc5Settings<W>,
    ) -> Result<Vec<u8>, Error>;

    /// Encode by RC5 with default settings (32/12/b)
    ///
    /// Check 4.1 in [the specification](https://www.grc.com/r&d/rc5.pdf).
    /// This function splits `Self` into blocks
    /// (pair of words) and executes the RC5 encryption algorithm
    /// `Error` - if `&self` cannot be divided into blocks!
    fn encode_rc5(&self, key: impl Key) -> Result<Vec<u8>, Error> {
        self.encode_rc5_with_settings(key, Rc5Settings::default())
    }
}

pub trait DecodeRc5 {
    /// Decode by RC5 with custom settings
    ///
    /// Check 4.1 in [the specification](https://www.grc.com/r&d/rc5.pdf).
    /// This function splits `Self` into blocks
    /// (pair of words) and executes the RC5 encryption algorithm
    /// `Error` - if `&self` cannot be divided into blocks!
    fn decode_rc5_with_settings<W: Word>(
        &self,
        key: impl Key,
        settings: Rc5Settings<W>,
    ) -> Result<Vec<u8>, Error>;

    /// Decode by RC5 with default settings (32/12/b)
    ///
    /// Check 4.1 in [the specification](https://www.grc.com/r&d/rc5.pdf).
    /// This function splits `Self` into blocks
    /// (pair of words) and executes the RC5 encryption algorithm
    /// `Error` - if `&self` cannot be divided into blocks!
    fn decode_rc5(&self, key: impl Key) -> Result<Vec<u8>, Error> {
        self.decode_rc5_with_settings(key, Rc5Settings::default())
    }
}

impl<T: EncodeAsBlocks> EncodeRc5 for T {
    fn encode_rc5_with_settings<W: Word>(
        &self,
        key: impl Key,
        settings: Rc5Settings<W>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.encode_as_blocks::<W>(key, settings.rounds_count)?)
    }
}

impl<T: DecodeAsBlocks> DecodeRc5 for T {
    fn decode_rc5_with_settings<W: Word>(
        &self,
        key: impl Key,
        settings: Rc5Settings<W>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self.decode_as_blocks::<W>(key, settings.rounds_count)?)
    }
}

#[cfg(test)]
mod tests;
