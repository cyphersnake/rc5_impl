use crate::word::{PresudoRandomKeySequenceIterator, RotateWordLeft, Word};

pub trait Key {
    /// Key length.
    /// Anyone implementing their own key type
    /// must provide the length of the key beforehand,
    /// and also make sure it fits in u8, which automatically
    /// implies a length limit of 0 to 255 inclusive
    const SIZE_HINT: u8;
    fn secret(&self) -> &[u8];
}

/// Converting the Secret Key from Bytes to Words
///
/// Copy the Secret key `K[0..b-1]` into an array `L[0..c-1]`
/// of `c = [b/u]` words, where `u = w/8` is the number of bytes\words.
/// Any unfilled byte positions of `L` are zeroes. In the case that
/// `b = c = 0` we reset `c` to `1` and set `L[0]` to zero.
fn expand_key_to_words<W: Word, K: Key>(key: &K) -> Vec<W> {
    let len = K::SIZE_HINT.max(1) as usize / W::BYTES;
    let mut words = vec![W::zero(); len];

    for index_secret in (0..K::SIZE_HINT).rev() {
        let word_index = index_secret as usize / W::BYTES;

        words[word_index] = words[word_index]
            .rotate_word_left(<W as From<u8>>::from(8u8))
            .wrapping_add(&<W as From<u8>>::from(key.secret()[index_secret as usize]));
    }

    words
}

pub(crate) trait MixinKey: Key + Sized {
    /// RC5 Key Mixin Function
    /// Mix the secret key and presudo random key sequence
    /// Check 4.3 in [the specification](https://www.grc.com/r&d/rc5.pdf).
    fn mixin<W: Word>(&self, rounds_count: u8) -> Vec<W> {
        let mut mixed_key =
            PresudoRandomKeySequenceIterator::<W>::collect_for_rounds_count(rounds_count);
        let mut key_words = expand_key_to_words::<W, Self>(self);

        let (mut a, mut b) = (W::zero(), W::zero());
        let (mut i, mut j) = (0, 0);

        for _ in 0..(3 * mixed_key.len().max(key_words.len())) {
            a = mixed_key[i]
                .wrapping_add(&a)
                .wrapping_add(&b)
                .rotate_left(3);
            mixed_key[i] = a;

            b = key_words[j]
                .wrapping_add(&a)
                .wrapping_add(&b)
                .rotate_word_left(a.wrapping_add(&b));
            key_words[j] = b;

            i = (i + 1) % mixed_key.len();
            j = (j + 1) % key_words.len();
        }

        mixed_key
    }
}
impl<K: Key + Sized> MixinKey for K {}

#[cfg(feature = "secrecy")]
use secrecy::ExposeSecret;

macro_rules! impl_key_for_array {
    ($($len:expr),+) => {
        $(
            impl Key for [u8; $len] {
                const SIZE_HINT: u8 = $len;
                fn secret(&self) -> &[u8] {
                    self.as_ref()
                }
            }

            #[cfg(feature = "secrecy")]
            impl Key for secrecy::Secret<[u8; $len]> {
                const SIZE_HINT: u8 = $len;
                fn secret(&self) -> &[u8] {
                    self.expose_secret()
                }
            }
        )+
    };
}

// TODO There is a better way through procedural macros, but I didn't quickly find
// a crate that would cover this functionality.
// Maybe implement in near future!
impl_key_for_array! {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
    23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62,
    63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82,
    83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101,
    102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
    118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133,
    134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
    150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165,
    166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181,
    182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197,
    198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213,
    214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229,
    230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245,
    246, 247, 248, 249, 250, 251, 252, 253, 254, 255
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_key_to_u8_words() {
        let key: [u8; 100] = (0..100).collect::<Vec<_>>().try_into().unwrap();
        assert_eq!(expand_key_to_words::<u8, [u8; 100]>(&key), key);
    }

    #[test]
    fn test_expand_key_to_u16_words() {
        let key: [u8; 100] = (0..100).collect::<Vec<_>>().try_into().unwrap();
        assert_eq!(
            expand_key_to_words::<u16, [u8; 100]>(&key),
            [
                256, 770, 1284, 1798, 2312, 2826, 3340, 3854, 4368, 4882, 5396, 5910, 6424, 6938,
                7452, 7966, 8480, 8994, 9508, 10022, 10536, 11050, 11564, 12078, 12592, 13106,
                13620, 14134, 14648, 15162, 15676, 16190, 16704, 17218, 17732, 18246, 18760, 19274,
                19788, 20302, 20816, 21330, 21844, 22358, 22872, 23386, 23900, 24414, 24928, 25442
            ]
        );
    }

    #[test]
    fn test_expand_key_to_u32_words() {
        let key: [u8; 100] = (0..100).collect::<Vec<_>>().try_into().unwrap();
        assert_eq!(
            expand_key_to_words::<u32, [u8; 100]>(&key),
            [
                50462976, 117835012, 185207048, 252579084, 319951120, 387323156, 454695192,
                522067228, 589439264, 656811300, 724183336, 791555372, 858927408, 926299444,
                993671480, 1061043516, 1128415552, 1195787588, 1263159624, 1330531660, 1397903696,
                1465275732, 1532647768, 1600019804, 1667391840
            ]
        );
    }

    #[test]
    fn test_expand_key_to_u64_words() {
        let key: [u8; 128] = (0..128).collect::<Vec<_>>().try_into().unwrap();
        assert_eq!(
            expand_key_to_words::<u64, [u8; 128]>(&key),
            [
                506097522914230528,
                1084818905618843912,
                1663540288323457296,
                2242261671028070680,
                2820983053732684064,
                3399704436437297448,
                3978425819141910832,
                4557147201846524216,
                5135868584551137600,
                5714589967255750984,
                6293311349960364368,
                6872032732664977752,
                7450754115369591136,
                8029475498074204520,
                8608196880778817904,
                9186918263483431288
            ]
        );
    }

    #[test]
    fn test_mixin() {
        let key: [u8; 128] = (0..128).collect::<Vec<_>>().try_into().unwrap();
        assert_eq!(key.mixin::<u8>(1), [168, 6, 50, 92]);
        assert_eq!(key.mixin::<u16>(1), [21542, 9370, 17770, 62430]);
        assert_eq!(
            key.mixin::<u32>(1),
            [2854821115, 2277703324, 1905444131, 1032546232]
        );
        assert_eq!(
            key.mixin::<u64>(1),
            [
                12723797007543140178,
                8506846885001948740,
                92597271829173040,
                9830834989226132594
            ]
        );
        assert_eq!(
            key.mixin::<u128>(1),
            [
                114286276042449365625390575719892940390,
                261757733981050994600817605645092027194,
                331116414727359757038381651340974201142,
                322073851914563924524269393118185725356
            ]
        );
    }
}
