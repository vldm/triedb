//! Merkle nibble types.

use std::{
    cmp::min,
    hash::Hash,
    ops::{Bound, RangeBounds},
};

use rlp::{Rlp, RlpStream};

use crate::Result;

/// Represents a nibble. A 16-variant value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Nibble {
    N0 = 0,
    N1,
    N2,
    N3,
    N4,
    N5,
    N6,
    N7,
    N8,
    N9,
    N10,
    N11,
    N12,
    N13,
    N14,
    N15,
}

impl From<usize> for Nibble {
    fn from(val: usize) -> Nibble {
        match val {
            0 => Nibble::N0,
            1 => Nibble::N1,
            2 => Nibble::N2,
            3 => Nibble::N3,
            4 => Nibble::N4,
            5 => Nibble::N5,
            6 => Nibble::N6,
            7 => Nibble::N7,
            8 => Nibble::N8,
            9 => Nibble::N9,
            10 => Nibble::N10,
            11 => Nibble::N11,
            12 => Nibble::N12,
            13 => Nibble::N13,
            14 => Nibble::N14,
            15 => Nibble::N15,
            _ => panic!(),
        }
    }
}

impl From<Nibble> for usize {
    fn from(nibble: Nibble) -> usize {
        nibble as usize
    }
}

impl From<u8> for Nibble {
    fn from(val: u8) -> Nibble {
        match val {
            0 => Nibble::N0,
            1 => Nibble::N1,
            2 => Nibble::N2,
            3 => Nibble::N3,
            4 => Nibble::N4,
            5 => Nibble::N5,
            6 => Nibble::N6,
            7 => Nibble::N7,
            8 => Nibble::N8,
            9 => Nibble::N9,
            10 => Nibble::N10,
            11 => Nibble::N11,
            12 => Nibble::N12,
            13 => Nibble::N13,
            14 => Nibble::N14,
            15 => Nibble::N15,
            _ => panic!(),
        }
    }
}

impl From<Nibble> for u8 {
    fn from(nibble: Nibble) -> u8 {
        nibble as u8
    }
}

/// A nibble type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NibbleType {
    Leaf,
    Extension,
}

/// A nibble vector.
pub type NibbleVec = Vec<Nibble>;
/// A nibble slice.
pub type NibbleSlice<'a> = &'a [Nibble];

/// Given a key, return the corresponding nibble.
pub fn from_key(key: &[u8]) -> NibbleVec {
    let mut vec = NibbleVec::new();

    for i in 0..(key.len() * 2) {
        if i & 1 == 0 {
            // even
            vec.push(((key[i / 2] & 0xf0) >> 4).into());
        } else {
            vec.push((key[i / 2] & 0x0f).into());
        }
    }

    vec
}

/// Given a nibble, return the corresponding key.
pub fn into_key(nibble: NibbleSlice) -> Vec<u8> {
    let mut ret = Vec::new();

    for i in 0..nibble.len() {
        let value: u8 = nibble[i].into();
        if i & 1 == 0 {
            // even
            ret.push(value << 4);
        } else {
            ret[i / 2] |= value;
        }
    }

    ret
}

/// Decode a nibble from RLP.
pub fn decode(rlp: &Rlp) -> Result<(NibbleVec, NibbleType)> {
    let mut vec = NibbleVec::new();

    let data = rlp.data()?;
    let start_odd = data[0] & 0b00010000 == 0b00010000;
    let start_index = if start_odd { 1 } else { 2 };
    let is_leaf = data[0] & 0b00100000 == 0b00100000;

    let len = data.len() * 2;

    for i in start_index..len {
        if i & 1 == 0 {
            // even
            vec.push(((data[i / 2] & 0xf0) >> 4).into());
        } else {
            vec.push((data[i / 2] & 0x0f).into());
        }
    }

    Ok((
        vec,
        if is_leaf {
            NibbleType::Leaf
        } else {
            NibbleType::Extension
        },
    ))
}

/// Encode a nibble into the given RLP stream.
pub fn encode(vec: NibbleSlice, typ: NibbleType, s: &mut RlpStream) {
    let mut ret: Vec<u8> = Vec::new();

    if vec.len() & 1 == 0 {
        // even
        ret.push(0b00000000);

        for (i, val) in vec.iter().enumerate() {
            if i & 1 == 0 {
                let v: u8 = (*val).into();
                ret.push(v << 4);
            } else {
                let end = ret.len() - 1;
                let v: u8 = (*val).into();
                ret[end] |= v;
            }
        }
    } else {
        ret.push(0b00010000);

        for (i, val) in vec.iter().enumerate() {
            if i & 1 == 0 {
                let end = ret.len() - 1;
                let v: u8 = (*val).into();
                ret[end] |= v;
            } else {
                let v: u8 = (*val).into();
                ret.push(v << 4);
            }
        }
    }

    ret[0] |= match typ {
        NibbleType::Leaf => 0b00100000,
        NibbleType::Extension => 0b00000000,
    };

    s.append(&ret);
}

/// Common prefix for two nibbles.
pub fn common<'a, 'b>(a: NibbleSlice<'a>, b: NibbleSlice<'b>) -> NibbleSlice<'a> {
    let mut common_len = 0;

    for i in 0..min(a.len(), b.len()) {
        if a[i] == b[i] {
            common_len += 1;
        } else {
            break;
        }
    }

    &a[0..common_len]
}

/// Common prefix for two nibbles. Return the sub nibbles.
pub fn common_with_sub<'a, 'b>(
    a: NibbleSlice<'a>,
    b: NibbleSlice<'b>,
) -> (NibbleSlice<'a>, NibbleVec, NibbleVec) {
    let common = common(a, b);
    let asub = a[common.len()..].into();
    let bsub = b[common.len()..].into();

    (common, asub, bsub)
}

/// Common prefix for all provided nibbles.
pub fn common_all<'a, T: Iterator<Item = NibbleSlice<'a>>>(mut iter: T) -> NibbleSlice<'a> {
    let first = match iter.next() {
        Some(val) => val,
        None => return &[],
    };
    let second = match iter.next() {
        Some(val) => val,
        None => return first,
    };

    let mut common_cur = common(first, second);
    for key in iter {
        common_cur = common(common_cur, key);
    }

    common_cur
}

// struct
trait NibbleIndex {
    type Slice<'b>
    where
        Self: 'b;
    fn get_nibble(&self, index: usize) -> Option<Nibble>;

    fn get_slice<R>(&self, range: R) -> Self::Slice<'_>
    where
        R: RangeBounds<usize>;
    fn is_even(&self) -> bool;
}

impl NibbleIndex for NibbleVec {
    type Slice<'b> = NibbleSlice<'b>;
    fn get_nibble(&self, index: usize) -> Option<Nibble> {
        self.get(index).copied()
    }
    fn is_even(&self) -> bool {
        self.len() % 2 == 0
    }

    // duplicate because we cant propagate this method to NibbleSlice::get_slice implementation.
    // because it's &self require additional temp reference
    fn get_slice<R>(&self, range: R) -> Self::Slice<'_>
    where
        R: RangeBounds<usize>,
    {
        match (range.start_bound(), range.end_bound()) {
            (Bound::Unbounded, Bound::Unbounded) => &self[..],
            (Bound::Unbounded, Bound::Included(&x)) => &self[..=x],
            (Bound::Unbounded, Bound::Excluded(&x)) => &self[..x],
            (Bound::Included(&x), Bound::Unbounded) => &self[x..],
            (Bound::Included(&x), Bound::Included(&y)) => &self[x..=y],
            (Bound::Included(&x), Bound::Excluded(&y)) => &self[x..y],
            (Bound::Excluded(_), _) => unreachable!(),
        }
    }
}

impl<'a> NibbleIndex for NibbleSlice<'a> {
    type Slice<'b> = NibbleSlice<'b>
    where Self: 'b
    ;
    fn get_nibble(&self, index: usize) -> Option<Nibble> {
        self.get(index).copied()
    }
    fn is_even(&self) -> bool {
        self.len() % 2 == 0
    }
    fn get_slice<R>(&self, range: R) -> Self::Slice<'_>
    where
        R: RangeBounds<usize>,
    {
        match (range.start_bound(), range.end_bound()) {
            (Bound::Unbounded, Bound::Unbounded) => &self[..],
            (Bound::Unbounded, Bound::Included(&x)) => &self[..=x],
            (Bound::Unbounded, Bound::Excluded(&x)) => &self[..x],
            (Bound::Included(&x), Bound::Unbounded) => &self[x..],
            (Bound::Included(&x), Bound::Included(&y)) => &self[x..=y],
            (Bound::Included(&x), Bound::Excluded(&y)) => &self[x..y],
            (Bound::Excluded(_), _) => unreachable!(),
        }
    }
}

#[derive(Debug)]
struct MyNibbleSlice<'a> {
    bytes: &'a [u8],

    skip_first: bool,
    skip_last: bool,
}

impl<'a> MyNibbleSlice<'a> {
    // Get slice from key bytes
    // Key bytes always has first nibble.
    // But we can allow skip last nibble.
    fn from_raw_key(bytes: &'a [u8], even: bool) -> Self {
        Self {
            bytes,
            skip_first: false,
            skip_last: !even,
        }
    }
    // Get slice from rlp representation
    // if even, it always contain first garbage byte which can be skipped on creation.
    // If odd, it contain only half byte of garbage, it should be skipped through skip_first flag
    // The latest byte is always two nibbles.
    fn from_raw_rlp(bytes: &'a [u8], even: bool) -> Self {
        if even {
            Self {
                bytes: &bytes[1..],
                skip_first: false,
                skip_last: false,
            }
        } else {
            Self {
                bytes,
                skip_first: true,
                skip_last: false,
            }
        }
    }

    fn pos(&self, mut index: usize) -> (usize, bool) {
        if self.skip_first {
            index = index.saturating_add(1);
        };
        let index_in_bytes = index / 2;
        let even = index % 2 != 0;
        (index_in_bytes, even)
    }

    fn len(&self) -> usize {
        let mut len = self.bytes.len() * 2;
        if self.skip_first {
            len -= 1;
        }
        if self.skip_last {
            len -= 1;
        }
        len
    }
}
impl<'a> NibbleIndex for MyNibbleSlice<'a> {
    type Slice<'b> = MyNibbleSlice<'b>
    where Self: 'b
    ;
    fn is_even(&self) -> bool {
        self.skip_first == self.skip_last
    }
    fn get_nibble(&self, index: usize) -> Option<Nibble> {
        if index >= self.len() {
            return None;
        }
        let (index_in_bytes, even) = dbg!(self.pos(index));
        self.bytes.get(index_in_bytes).map(|v| {
            if even {
                Nibble::from(*v & 0x0f)
            } else {
                Nibble::from((*v & 0xf0) >> 4)
            }
        })
    }
    fn get_slice<R>(&self, range: R) -> Self::Slice<'_>
    where
        R: RangeBounds<usize>,
    {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_into_key() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 244, 233, 188];

        assert_eq!(key, into_key(&from_key(&key)));
    }
    #[test]
    fn simple_get() {
        let mut nibbles = NibbleVec::new();

        nibbles.push(Nibble::N10);
        nibbles.push(Nibble::N11);
        nibbles.push(Nibble::N12);

        assert_eq!(nibbles.len(), 3);
        assert!(!nibbles.is_even());
        nibbles.push(Nibble::N13);
        nibbles.push(Nibble::N14);
        nibbles.push(Nibble::N15);
        assert_eq!(nibbles.len(), 6);
        assert!(nibbles.is_even());

        assert_eq!(nibbles.get_nibble(0), Some(Nibble::N10));
        assert_eq!(nibbles.get_nibble(1), Some(Nibble::N11));
        assert_eq!(nibbles.get_nibble(2), Some(Nibble::N12));

        assert_eq!(nibbles.get_nibble(3), Some(Nibble::N13));
        assert_eq!(nibbles.get_nibble(4), Some(Nibble::N14));
        assert_eq!(nibbles.get_nibble(5), Some(Nibble::N15));
        assert_eq!(nibbles.get_nibble(5), Some(Nibble::N15));
        assert_eq!(nibbles.get_nibble(6), None);
    }

    #[test]
    fn simple_get_my_nibble() {
        let key = vec![0x12, 0xde, 0xad];
        let my_nibble = MyNibbleSlice::from_raw_key(&key, true);
        assert!(my_nibble.is_even());
        assert!(!my_nibble.skip_first);
        assert!(!my_nibble.skip_last);
        assert_eq!(my_nibble.get_nibble(0), Some(Nibble::N1));
        assert_eq!(my_nibble.get_nibble(1), Some(Nibble::N2));

        assert_eq!(my_nibble.get_nibble(2), Some(Nibble::N13));
        assert_eq!(my_nibble.get_nibble(3), Some(Nibble::N14));

        assert_eq!(my_nibble.get_nibble(4), Some(Nibble::N10));
        assert_eq!(my_nibble.get_nibble(5), Some(Nibble::N13));
        assert_eq!(my_nibble.get_nibble(6), None);
    }

    #[test]
    fn rlp_slice_encoded() {
        let mut nibbles = NibbleVec::new();

        nibbles.push(Nibble::N10);
        nibbles.push(Nibble::N11);
        nibbles.push(Nibble::N12);

        assert_eq!(nibbles.len(), 3);
        assert!(!nibbles.is_even());

        let mut rlp = RlpStream::new();
        encode(&nibbles, NibbleType::Leaf, &mut rlp);
        let bytes = rlp.as_raw();
        // first byte is rlp len - skip it
        let my_nibble = MyNibbleSlice::from_raw_rlp(&bytes[1..], false);
        dbg!(&my_nibble);
        assert_eq!(my_nibble.get_nibble(0), Some(Nibble::N10));
        assert_eq!(my_nibble.get_nibble(1), Some(Nibble::N11));
        assert_eq!(my_nibble.get_nibble(2), Some(Nibble::N12));

        assert_eq!(my_nibble.get_nibble(3), None);

        nibbles.push(Nibble::N13);
        nibbles.push(Nibble::N14);
        nibbles.push(Nibble::N15);
        assert_eq!(nibbles.len(), 6);
        assert!(nibbles.is_even());

        let mut rlp = RlpStream::new();
        encode(&nibbles, NibbleType::Leaf, &mut rlp);
        let bytes = rlp.as_raw();
        // first byte is rlp len - skip it
        let my_nibble = MyNibbleSlice::from_raw_rlp(&bytes[1..], true);

        assert_eq!(my_nibble.get_nibble(0), Some(Nibble::N10));
        assert_eq!(my_nibble.get_nibble(1), Some(Nibble::N11));
        assert_eq!(my_nibble.get_nibble(2), Some(Nibble::N12));
        assert_eq!(my_nibble.get_nibble(3), Some(Nibble::N13));
        assert_eq!(my_nibble.get_nibble(4), Some(Nibble::N14));
        assert_eq!(my_nibble.get_nibble(5), Some(Nibble::N15));

        assert_eq!(my_nibble.get_nibble(6), None);
    }
}
