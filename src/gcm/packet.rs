/// represents encryped GCM data
pub struct Packet {
    value: Vec<u8>,
}

const MIN_PACKET_SIZE: usize = 28;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

impl Packet {
    #[inline]
    pub fn nonce(&self) -> Nonce {
        Nonce(&self.value[0..NONCE_SIZE])
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        todo!();
    }

    #[inline]
    pub fn additional_data(&self) -> &[u8] {
        todo!();
    }

    #[inline]
    pub fn tag(&self) -> Tag {
        let len = self.value.len();
        Tag(&self.value[len - TAG_SIZE..len])
    }
}

pub struct TooShortError;
pub struct TryFromSliceError;

impl TryFrom<Vec<u8>> for Packet {
    type Error = TooShortError;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        match data.len() >= MIN_PACKET_SIZE {
            true => Ok(Packet { value: data }),
            false => Err(TooShortError),
        }
    }
}

impl Into<Vec<u8>> for Packet {
    fn into(self) -> Vec<u8> {
        self.value
    }
}

/// a slice with a guaranteed length of `TAG_SIZE`
#[derive(PartialEq)]
pub struct Tag<'a>(&'a [u8]);

impl<'a> TryFrom<&'a [u8]> for Tag<'a> {
    type Error = TryFromSliceError;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        match value.len() == TAG_SIZE {
            true => Ok(Tag(value)),
            false => Err(TryFromSliceError),
        }
    }
}

impl<'a> Into<&'a [u8]> for Tag<'a> {
    fn into(self) -> &'a [u8] {
        self.0
    }
}

/// a slice with a guaranteed length of `NONCE_SIZE`
#[derive(PartialEq)]
pub struct Nonce<'a>(&'a [u8]);

impl<'a> TryFrom<&'a [u8]> for Nonce<'a> {
    type Error = TryFromSliceError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        match value.len() == NONCE_SIZE {
            true => Ok(Nonce(value)),
            false => Err(TryFromSliceError),
        }
    }
}

impl<'a> Into<&'a [u8]> for Nonce<'a> {
    fn into(self) -> &'a [u8] {
        self.0
    }
}
