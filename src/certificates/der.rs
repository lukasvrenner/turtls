use core::iter::Iterator;

pub(crate) struct DerObj<'a> {
    /// The DER tag.
    ///
    /// Although larger tags are technically allowed,
    /// this implementation assumes every tag is one byte.
    tag: u8,
    data: &'a [u8],
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
            println!("{:x?}", &self.der_objs[2..][..num_len_bytes]);
            for i in 0..num_len_bytes {
                len |= (self.der_objs[2 + i] as usize) << 8 * (num_len_bytes - i - 1);
            }
            println!("{:x}", len);

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
