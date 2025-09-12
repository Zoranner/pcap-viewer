//! 显示工具函数

/// 显示原始数据为ASCII字符
pub fn display_raw_data_as_ascii(data: &[u8]) -> String {
    data.iter()
        .map(|&byte| {
            if (32..=126).contains(&byte) {
                byte as char
            } else {
                '.'
            }
        })
        .collect()
}

/// 格式化文件头信息
pub fn format_file_header_info(data: &[u8]) -> Option<String> {
    if data.len() < 16 {
        return None;
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let major_ver = u16::from_le_bytes([data[4], data[5]]);
    let minor_ver = u16::from_le_bytes([data[6], data[7]]);
    let tz_offset = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let ts_accuracy = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);

    Some(format!(
        " MAGIC: 0x{:08X} VER: {}.{} TZ: {} TS_ACC: {}",
        magic, major_ver, minor_ver, tz_offset, ts_accuracy
    ))
}
