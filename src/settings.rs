use std::marker::PhantomData;

use crate::word::Word;

pub type DefaultWord = u32;

pub struct Rc5Settings<W: Word> {
    pub rounds_count: u8,
    _p: PhantomData<W>,
}
impl<W: Word> Rc5Settings<W> {
    pub fn new(rounds_count: u8) -> Self {
        Self {
            rounds_count,
            _p: PhantomData::default(),
        }
    }
}
impl Default for Rc5Settings<DefaultWord> {
    fn default() -> Self {
        Self {
            rounds_count: 12,
            _p: PhantomData::default(),
        }
    }
}
