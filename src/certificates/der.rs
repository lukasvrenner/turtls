use core::iter::Iterator;

pub(crate) enum DerTag {
    Boolean = 0x01,
    Integer = 0x02,
    BitString = 0x03,
    OctetString = 0x04,
    Null = 0x05,
    ObjIdentifier = 0x06,
    ObjDesc = 0x07,
    External = 0x08,
    Real = 0x09,
    Enumerated = 0x0a,
    EmbededPdv = 0x0b,
    Utf8String = 0x0c,
    RelativeOid = 0x0d,
    Time = 0x0e,
    Reserved = 0x0f,
    Sequence = 0x30,
    Set = 0x31,
    NumericString = 0x12,
    PrintableString = 0x13,
    T61String = 0x14,
    VideotexString = 0x15,
    Ia5String = 0x16,
    UtcTime = 0x17,
    GeneralizedTime = 0x18,
    GraphicString = 0x19,
    VisibleString = 0x1a,
    GeneralString = 0x1b,
    UniversalString = 0x1c,
    CharacterString = 0x1d,
    BmpString = 0x1e,
    LongForm = 0x1f,
}

pub(crate) enum DerClass {
    Universal = 0x00,
    Application = 0x40,
    ContextSpecific = 0x80,
    Private = 0xc0,
}

pub(crate) enum DerPrimCon {
    Primitive = 0x00,
    Constructed = 0x20,

}

pub(crate) const fn der_gen_tag(class: DerClass, prim_con: DerPrimCon, num: u8) -> u8 {
    class as u8 | prim_con as u8 | der_get_num(num)
}

pub(crate) const fn der_is_constructed(tag: u8) -> bool {
    tag & 0x20 != 0
}

pub(crate) const fn der_get_num(tag: u8) -> u8 {
    tag & 0x1f
}

pub(crate) const fn der_get_class(tag: u8) -> DerClass {
    match tag & 0xc0 {
        0x00 => DerClass::Universal,
        0x40 => DerClass::Application,
        0x80 => DerClass::ContextSpecific,
        0xc0 => DerClass::Private,
        _ => unreachable!(),
    }
}

pub(crate) struct DerObj<'a> {
    /// The DER tag.
    ///
    /// Although larger tags are technically allowed,
    /// this implementation assumes every tag is one byte.
    pub(crate) tag: u8,
    pub(crate) data: &'a [u8],
}

pub(crate) struct DerIter<'a> {
    der_objs: &'a [u8],
}

impl<'a> DerIter<'a> {
    pub(crate) fn new(der_objs: &'a [u8]) -> Self {
        Self { der_objs }
    }
}

impl<'a> Iterator for DerIter<'a> {
    type Item = DerObj<'a>;

    fn next(&mut self) -> Option<DerObj<'a>> {
        if self.der_objs.len() < 2 {
            return None;
        }

        let tag = self.der_objs[0];

        // Only accept one-byte tags.
        if tag & 0x1f == 0x1f {
            return None;
        }


        let mut len: usize = 0;

        let mut pos: usize = 2;

        if self.der_objs[1] > 127 {
            let num_len_bytes = (self.der_objs[1] & 0x7f) as usize;
            // Do not accept extremely large objects.
            if num_len_bytes > 4 || num_len_bytes > self.der_objs.len() - 2 {
                return None;
            }
            for i in 0..num_len_bytes {
                len |= (self.der_objs[2 + i] as usize) << 8 * (num_len_bytes - i - 1);
            }

            pos += num_len_bytes;
        } else {
            len = self.der_objs[1] as usize;
        }

        if len > self.der_objs.len() - pos {
            return None;
        }

        let data = &self.der_objs[pos..][..len];

        self.der_objs = &self.der_objs[pos + len..];


        return Some(DerObj {
            tag,
            data,
        });

    }
}
