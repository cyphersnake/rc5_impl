use std::{error, fmt};

mod key;
pub use key::Key;

mod word;
pub use word::Word;

mod block;
use block::{DecodeBlocks, EncodeBlocks};

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
    fn encode_rc5_with_settings<W: Word>(
        &self,
        key: impl Key,
        settings: Rc5Settings<W>,
    ) -> Result<Vec<u8>, Error>;

    fn encode_rc5(&self, key: impl Key) -> Result<Vec<u8>, Error> {
        self.encode_rc5_with_settings(key, Rc5Settings::default())
    }
}

pub trait DecodeRc5 {
    fn decode_rc5_with_settings<W: Word>(
        &self,
        key: impl Key,
        settings: Rc5Settings<W>,
    ) -> Result<Vec<u8>, Error>;

    fn decode_rc5(&self, key: impl Key) -> Result<Vec<u8>, Error> {
        self.decode_rc5_with_settings(key, Rc5Settings::default())
    }
}

impl<T: AsRef<[u8]>> EncodeRc5 for T {
    fn encode_rc5_with_settings<W: Word>(
        &self,
        key: impl Key,
        settings: Rc5Settings<W>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .as_ref()
            .encode_blocks::<W>(key, settings.rounds_count)?)
    }
}

impl<T: AsRef<[u8]>> DecodeRc5 for T {
    fn decode_rc5_with_settings<W: Word>(
        &self,
        key: impl Key,
        settings: Rc5Settings<W>,
    ) -> Result<Vec<u8>, Error> {
        Ok(self
            .as_ref()
            .decode_blocks::<W>(key, settings.rounds_count)?)
    }
}

#[cfg(test)]
mod tests;
