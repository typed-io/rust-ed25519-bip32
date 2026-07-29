use core::fmt;

pub fn encode(input: &[u8], f: &mut fmt::Formatter) -> fmt::Result {
    for byte in input.iter() {
        write!(f, "{:02x}", byte)?;
    }
    Ok(())
}
