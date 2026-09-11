//! Bounds-checked little-endian reads shared by the binary parsers.

use anyhow::{Context, Result};

#[inline]
pub(crate) fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes: [u8; 2] = data
        .get(offset..offset + 2)
        .context("truncated u16")?
        .try_into()?;
    Ok(u16::from_le_bytes(bytes))
}

#[inline]
pub(crate) fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .context("truncated u32")?
        .try_into()?;
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian_and_rejects_truncation() {
        let data = [0x34, 0x12, 0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u16(&data, 0).unwrap(), 0x1234);
        assert_eq!(read_u32(&data, 2).unwrap(), 0x1234_5678);
        assert!(read_u16(&data, 5).is_err());
        assert!(read_u32(&data, 3).is_err());
        assert!(read_u16(&[], 0).is_err());
    }
}
