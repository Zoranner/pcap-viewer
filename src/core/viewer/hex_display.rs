//! 十六进制显示逻辑模块

use colored::*;
use crate::core::pcap::parser::{DataPacket, PcapFileHeader};

/// 十六进制显示器
pub struct HexDisplayer {
    bytes_per_line: usize,
    use_color: bool,
}

impl HexDisplayer {
    /// 创建新的十六进制显示器
    pub fn new(bytes_per_line: usize, use_color: bool) -> Self {
        Self {
            bytes_per_line,
            use_color,
        }
    }

    /// 显示十六进制行（带解析信息）
    pub fn display_hex_line_with_parsing(
        &self,
        offset: usize,
        data: &[u8],
        line_number: usize,
        bytes_per_line: usize,
        parser: &crate::core::pcap::parser::PcapParser,
    ) -> String {
        let mut output = String::new();

        // 计算当前行的起始偏移
        let start_offset = offset + line_number * bytes_per_line;

        // 偏移地址（8位十六进制）
        let offset_str = format!("{:08X}", start_offset);
        output.push_str(&if self.use_color {
            offset_str.bright_blue().to_string()
        } else {
            offset_str
        });

        output.push_str("  ");

        // 十六进制数据
        let line_start = line_number * bytes_per_line;
        let line_end = (line_start + bytes_per_line).min(data.len());

        for i in line_start..line_end {
            if i < data.len() {
                let hex_str = format!("{:02X}", data[i]);
                output.push_str(&if self.use_color {
                    if data[i].is_ascii_graphic() || data[i] == b' ' {
                        hex_str.green().to_string()
                    } else if data[i] == 0 {
                        hex_str.bright_black().to_string()
                    } else {
                        hex_str.yellow().to_string()
                    }
                } else {
                    hex_str
                });
            } else {
                output.push_str("  ");
            }
            output.push(' ');

            // 每8个字节添加额外空格
            if (i + 1) % 8 == 0 {
                output.push(' ');
            }
        }

        // 补齐到固定宽度
        let hex_width = bytes_per_line * 3 + bytes_per_line / 8;
        let current_hex_len = (line_end - line_start) * 3 + (line_end - line_start) / 8;
        for _ in current_hex_len..hex_width {
            output.push(' ');
        }

        output.push_str("  |");

        // ASCII 表示
        for i in line_start..line_end {
            if i < data.len() {
                let ch = data[i];
                let ascii_char = if ch.is_ascii_graphic() || ch == b' ' {
                    ch as char
                } else {
                    '.'
                };

                let ascii_str = ascii_char.to_string();
                output.push_str(&if self.use_color {
                    if ch.is_ascii_graphic() || ch == b' ' {
                        ascii_str.green().to_string()
                    } else {
                        ascii_str.bright_black().to_string()
                    }
                } else {
                    ascii_str
                });
            } else {
                output.push(' ');
            }
        }

        output.push('|');

        // 添加解析信息
        let parsing_info = self.get_parsing_info(start_offset, &data[line_start..line_end], parser);
        if !parsing_info.is_empty() {
            output.push_str("  ");
            output.push_str(&parsing_info);
        }

        output
    }

    /// 显示十六进制行（简化版本，不带解析信息）
    pub fn display_hex_line(
        &self,
        offset: usize,
        data: &[u8],
        line_number: usize,
        bytes_per_line: usize,
    ) -> String {
        let mut output = String::new();

        // 计算当前行的起始偏移
        let start_offset = offset + line_number * bytes_per_line;

        // 偏移地址（8位十六进制）
        let offset_str = format!("{:08X}", start_offset);
        output.push_str(&if self.use_color {
            offset_str.bright_blue().to_string()
        } else {
            offset_str
        });

        output.push_str("  ");

        // 十六进制数据
        let line_start = line_number * bytes_per_line;
        let line_end = (line_start + bytes_per_line).min(data.len());

        for i in line_start..line_end {
            if i < data.len() {
                let hex_str = format!("{:02X}", data[i]);
                output.push_str(&if self.use_color {
                    if data[i].is_ascii_graphic() || data[i] == b' ' {
                        hex_str.green().to_string()
                    } else if data[i] == 0 {
                        hex_str.bright_black().to_string()
                    } else {
                        hex_str.yellow().to_string()
                    }
                } else {
                    hex_str
                });
            } else {
                output.push_str("  ");
            }
            output.push(' ');

            // 每8个字节添加额外空格
            if (i + 1) % 8 == 0 {
                output.push(' ');
            }
        }

        // 补齐到固定宽度
        let hex_width = bytes_per_line * 3 + bytes_per_line / 8;
        let current_hex_len = (line_end - line_start) * 3 + (line_end - line_start) / 8;
        for _ in current_hex_len..hex_width {
            output.push(' ');
        }

        output.push_str("  |");

        // ASCII 表示
        for i in line_start..line_end {
            if i < data.len() {
                let ch = data[i];
                let ascii_char = if ch.is_ascii_graphic() || ch == b' ' {
                    ch as char
                } else {
                    '.'
                };

                let ascii_str = ascii_char.to_string();
                output.push_str(&if self.use_color {
                    if ch.is_ascii_graphic() || ch == b' ' {
                        ascii_str.green().to_string()
                    } else {
                        ascii_str.bright_black().to_string()
                    }
                } else {
                    ascii_str
                });
            } else {
                output.push(' ');
            }
        }

        output.push('|');
        output
    }

    /// 显示原始数据
    pub fn display_raw_data(&self, data: &[u8]) -> Vec<String> {
        let mut lines = Vec::new();
        let total_lines = (data.len() + self.bytes_per_line - 1) / self.bytes_per_line;

        for line_number in 0..total_lines {
            let line = self.display_hex_line(0, data, line_number, self.bytes_per_line);
            lines.push(line);
        }

        lines
    }

    /// 显示文件头信息
    pub fn display_file_header_info(&self, header: &PcapFileHeader) -> Vec<String> {
        let mut lines = Vec::new();
        
        lines.push("=== PCAP 文件头信息 ===".to_string());
        lines.push(format!("魔数: 0x{:08X}", header.magic_number));
        lines.push(format!("主版本号: {}", header.major_version));
        lines.push(format!("次版本号: {}", header.minor_version));
        lines.push(format!("时区偏移: {}", header.timezone_offset));
        lines.push(format!("时间戳精度: {}", header.timestamp_accuracy));
        lines.push("".to_string());

        lines
    }

    /// 显示数据包信息
    pub fn display_packet_info(&self, packets: &[DataPacket]) -> Vec<String> {
        let mut lines = Vec::new();
        
        lines.push("=== 数据包信息 ===".to_string());
        lines.push(format!("总数据包数: {}", packets.len()));
        lines.push("".to_string());

        for (i, packet) in packets.iter().enumerate().take(10) {
            lines.push(format!("数据包 #{}", i + 1));
            lines.push(format!("  时间戳: {}.{:09}", 
                packet.header.timestamp_seconds, 
                packet.header.timestamp_nanoseconds));
            lines.push(format!("  数据长度: {} 字节", packet.header.packet_length));
            lines.push(format!("  校验和: 0x{:08X}", packet.header.checksum));
            lines.push("".to_string());
        }

        if packets.len() > 10 {
            lines.push(format!("... 还有 {} 个数据包", packets.len() - 10));
        }

        lines
    }

    /// 获取解析信息
    fn get_parsing_info(&self, offset: usize, data: &[u8], parser: &crate::core::pcap::parser::PcapParser) -> String {
        // 文件头区域 (0-15)
        if offset < 16 {
            return self.parse_file_header_field(offset, data);
        }

        // 查找对应的数据包
        if let Some(packet_info) = self.find_packet_at_offset(offset, parser) {
            return self.parse_packet_field(offset, data, packet_info);
        }

        String::new()
    }

    /// 解析文件头字段
    fn parse_file_header_field(&self, offset: usize, data: &[u8]) -> String {
        match offset {
            0..=3 => {
                let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                format!("Magic: 0x{:08X}", magic)
            }
            4..=5 => {
                let major = u16::from_le_bytes([data[0], data[1]]);
                format!("Major: {}", major)
            }
            6..=7 => {
                let minor = u16::from_le_bytes([data[0], data[1]]);
                format!("Minor: {}", minor)
            }
            8..=11 => {
                let tz = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                format!("TZ: {}", tz)
            }
            12..=15 => {
                let acc = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                format!("Acc: {}", acc)
            }
            _ => String::new(),
        }
    }

    /// 解析数据包字段
    fn parse_packet_field(&self, offset: usize, data: &[u8], packet_info: PacketInfo) -> String {
        let packet_start = packet_info.packet_offset;
        let field_offset = offset - packet_start;

        match field_offset {
            0..=3 => {
                let ts_sec = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                format!("TS: {}", ts_sec)
            }
            4..=7 => {
                let ts_nsec = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                format!("TSn: {}", ts_nsec)
            }
            8..=11 => {
                let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                format!("Len: {}", len)
            }
            12..=15 => {
                let checksum = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                format!("CRC: 0x{:08X}", checksum)
            }
            _ => {
                if field_offset >= 16 {
                    format!("Data[{}]", field_offset - 16)
                } else {
                    String::new()
                }
            }
        }
    }

    /// 查找指定偏移处的数据包信息
    fn find_packet_at_offset(&self, offset: usize, parser: &crate::core::pcap::parser::PcapParser) -> Option<PacketInfo> {
        let mut current_offset = 16; // 跳过文件头

        for (packet_index, packet) in parser.packets().iter().enumerate() {
            let packet_start = current_offset;
            let packet_end = packet_start + 16 + packet.header.packet_length as usize;

            if offset >= packet_start && offset < packet_end {
                return Some(PacketInfo {
                    packet_index,
                    packet_offset: packet_start,
                    packet_length: packet.header.packet_length as usize,
                });
            }

            current_offset = packet_end;
        }

        None
    }
}

/// 数据包信息
#[derive(Debug, Clone)]
struct PacketInfo {
    packet_index: usize,
    packet_offset: usize,
    packet_length: usize,
}
