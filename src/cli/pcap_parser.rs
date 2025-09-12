//! PCAP 文件解析器

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::app::error::types::Result;

/// PCAP 文件头结构 (16字节)
#[derive(Debug, Clone)]
pub struct PcapFileHeader {
    pub magic_number: u32,    // 0xD4C3B2A1
    pub major_version: u16,   // 0x0002
    pub minor_version: u16,   // 0x0004
    pub timezone_offset: u32, // 通常为 0
    pub timestamp_accuracy: u32, // 固定为 0
}

/// 数据包头部结构 (16字节)
#[derive(Debug, Clone)]
pub struct DataPacketHeader {
    pub timestamp_seconds: u32, // 时间戳秒部分 (UTC)
    pub timestamp_nanoseconds: u32, // 时间戳纳秒部分 (UTC)
    pub packet_length: u32,     // 数据包长度（字节）
    pub checksum: u32,          // 数据包校验和（CRC32）
}

/// 数据包结构
#[derive(Debug, Clone)]
pub struct DataPacket {
    pub header: DataPacketHeader,
}

/// PCAP 文件解析器
pub struct PcapParser {
    file_path: std::path::PathBuf,
    file_header: Option<PcapFileHeader>,
    packets: Vec<DataPacket>,
}

impl PcapParser {
    /// 创建新的 PCAP 解析器
    pub fn new<P: AsRef<Path>>(
        file_path: P,
    ) -> Result<Self> {
        let file_path = file_path.as_ref().to_path_buf();

        let mut parser = Self {
            file_path,
            file_header: None,
            packets: Vec::new(),
        };

        parser.parse_file()?;
        Ok(parser)
    }

    /// 解析整个文件
    fn parse_file(&mut self) -> Result<()> {
        let file = File::open(&self.file_path)?;
        let mut reader = BufReader::new(file);

        // 解析文件头
        self.file_header =
            Some(self.parse_file_header(&mut reader)?);

        // 解析所有数据包
        self.parse_packets(&mut reader)?;

        Ok(())
    }

    /// 解析文件头
    fn parse_file_header<R: Read>(
        &self,
        reader: &mut R,
    ) -> Result<PcapFileHeader> {
        let mut buffer = [0u8; 16];
        reader.read_exact(&mut buffer)?;

        let magic_number = u32::from_le_bytes([
            buffer[0], buffer[1], buffer[2], buffer[3],
        ]);
        let major_version =
            u16::from_le_bytes([buffer[4], buffer[5]]);
        let minor_version =
            u16::from_le_bytes([buffer[6], buffer[7]]);
        let timezone_offset = u32::from_le_bytes([
            buffer[8], buffer[9], buffer[10], buffer[11],
        ]);
        let timestamp_accuracy = u32::from_le_bytes([
            buffer[12], buffer[13], buffer[14], buffer[15],
        ]);

        // 验证文件格式
        if magic_number != 0xD4C3B2A1 {
            return Err(crate::app::error::types::PcapViewerError::InvalidFormat(
                format!("Invalid magic number: 0x{:08X}", magic_number)
            ).into());
        }
        if major_version != 0x0002
            || minor_version != 0x0004
        {
            return Err(crate::app::error::types::PcapViewerError::InvalidFormat(
                format!("Unsupported version: {}.{}", major_version, minor_version)
            ).into());
        }

        Ok(PcapFileHeader {
            magic_number,
            major_version,
            minor_version,
            timezone_offset,
            timestamp_accuracy,
        })
    }

    /// 解析所有数据包
    fn parse_packets<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> Result<()> {
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)?;

        let mut offset = 0;

        while offset < buffer.len() {
            if offset + 16 > buffer.len() {
                break; // 没有足够的数据读取数据包头
            }

            // 解析数据包头
            let header_bytes = &buffer[offset..offset + 16];
            let header =
                self.parse_packet_header(header_bytes);
            offset += 16;

            // 读取数据包数据
            if offset + header.packet_length as usize
                > buffer.len()
            {
                break; // 没有足够的数据读取数据包体
            }

            // 跳过数据包体数据
            offset += header.packet_length as usize;

            self.packets.push(DataPacket { header });
        }

        Ok(())
    }

    /// 解析数据包头
    fn parse_packet_header(
        &self,
        bytes: &[u8],
    ) -> DataPacketHeader {
        let timestamp_seconds = u32::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
        ]);
        let timestamp_nanoseconds = u32::from_le_bytes([
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let packet_length = u32::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11],
        ]);
        let checksum = u32::from_le_bytes([
            bytes[12], bytes[13], bytes[14], bytes[15],
        ]);

        DataPacketHeader {
            timestamp_seconds,
            timestamp_nanoseconds,
            packet_length,
            checksum,
        }
    }

    /// 获取文件头
    pub fn file_header(&self) -> Option<&PcapFileHeader> {
        self.file_header.as_ref()
    }

    /// 获取所有数据包
    pub fn packets(&self) -> &[DataPacket] {
        &self.packets
    }
}
