pub fn get_number_of_bytes_in_message(four_bytes: &[u8]) -> u32 {
    (((*four_bytes)[0] as u32) << 24)
        + (((*four_bytes)[1] as u32) << 16)
        + (((*four_bytes)[2] as u32) << 8)
        + (((*four_bytes)[3] as u32) << 0)
}
