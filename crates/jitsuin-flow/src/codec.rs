//! Byte writer and strict reader for the flow's own formats (deal snapshot, HNK-26.T10). Integers
//! are little endian, as in `jitsuin-core`; strings and byte strings carry a u16 length.

use jitsuin_board::{BoardRecord, Position};
use jitsuin_core::{BoardEntry, Seal, SEAL_LEN};

use crate::Error;

const BAD: Error = Error::Snapshot("malformed snapshot");

#[derive(Default)]
pub(crate) struct Writer {
    pub(crate) out: Vec<u8>,
}

impl Writer {
    pub(crate) fn byte(&mut self, b: u8) {
        self.out.push(b);
    }

    pub(crate) fn raw(&mut self, b: &[u8]) {
        self.out.extend_from_slice(b);
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.raw(&v.to_le_bytes());
    }

    pub(crate) fn u64(&mut self, v: u64) {
        self.raw(&v.to_le_bytes());
    }

    pub(crate) fn bytes(&mut self, b: &[u8]) -> Result<(), Error> {
        let len = u16::try_from(b.len()).map_err(|_| Error::Snapshot("field too long"))?;
        self.raw(&len.to_le_bytes());
        self.raw(b);
        Ok(())
    }

    pub(crate) fn str(&mut self, s: &str) -> Result<(), Error> {
        self.bytes(s.as_bytes())
    }

    pub(crate) fn strs(&mut self, list: &[String]) -> Result<(), Error> {
        let n = u16::try_from(list.len()).map_err(|_| Error::Snapshot("list too long"))?;
        self.raw(&n.to_le_bytes());
        list.iter().try_for_each(|s| self.str(s))
    }

    pub(crate) fn entry(&mut self, e: &BoardEntry) {
        let len = e.encoded_len();
        self.byte(len as u8);
        self.raw(&e.to_memo_bytes()[..len]);
    }

    pub(crate) fn record(&mut self, r: &BoardRecord) -> Result<(), Error> {
        self.str(&r.txid)?;
        self.u32(r.position.height);
        self.u32(r.position.tx_index);
        self.u32(r.position.output_index);
        self.entry(&r.entry);
        Ok(())
    }

    pub(crate) fn records(&mut self, list: &[BoardRecord]) -> Result<(), Error> {
        let n = u16::try_from(list.len()).map_err(|_| Error::Snapshot("list too long"))?;
        self.raw(&n.to_le_bytes());
        list.iter().try_for_each(|r| self.record(r))
    }

    pub(crate) fn seals(&mut self, seals: &[Seal]) -> Result<(), Error> {
        let n = u8::try_from(seals.len()).map_err(|_| Error::Snapshot("too many seals"))?;
        self.byte(n);
        seals.iter().for_each(|s| self.raw(&s.to_bytes()));
        Ok(())
    }
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, pos: 0 }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(BAD)?;
        let slice = self.bytes.get(self.pos..end).ok_or(BAD)?;
        self.pos = end;
        Ok(slice)
    }

    pub(crate) fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn u16(&mut self) -> Result<usize, Error> {
        Ok(usize::from(u16::from_le_bytes(self.array()?)))
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let len = self.u16()?;
        self.take(len)
    }

    pub(crate) fn str(&mut self) -> Result<String, Error> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| BAD)
    }

    pub(crate) fn strs(&mut self) -> Result<Vec<String>, Error> {
        (0..self.u16()?).map(|_| self.str()).collect()
    }

    pub(crate) fn entry(&mut self) -> Result<BoardEntry, Error> {
        let len = usize::from(self.byte()?);
        Ok(BoardEntry::from_memo_bytes(self.take(len)?)?)
    }

    pub(crate) fn record(&mut self) -> Result<BoardRecord, Error> {
        Ok(BoardRecord {
            txid: self.str()?,
            position: Position {
                height: self.u32()?,
                tx_index: self.u32()?,
                output_index: self.u32()?,
            },
            entry: self.entry()?,
        })
    }

    pub(crate) fn records(&mut self) -> Result<Vec<BoardRecord>, Error> {
        (0..self.u16()?).map(|_| self.record()).collect()
    }

    pub(crate) fn seals(&mut self) -> Result<Vec<Seal>, Error> {
        (0..self.byte()?)
            .map(|_| Ok(Seal::from_bytes(self.take(SEAL_LEN)?)?))
            .collect()
    }

    pub(crate) fn finish(&self) -> Result<(), Error> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Snapshot("trailing bytes"))
        }
    }
}
