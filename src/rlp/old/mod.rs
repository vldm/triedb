pub mod decode;
pub mod encode;

pub use decode::{Decodable, DecoderError};
pub use encode::Encodable;


pub use encode::encode;

pub use decode::decode;
pub use super::NibblePair;
