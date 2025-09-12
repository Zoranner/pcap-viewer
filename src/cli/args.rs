//! 命令行参数定义

use clap::Parser;
use std::path::PathBuf;

/// PCAP 文件查看器 - 支持自定义PCAP格式的十六进制查看工具
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct CliArgs {
    /// PCAP 文件路径
    pub file_path: PathBuf,
}

impl CliArgs {
    /// 获取每行显示的字节数（固定为16）
    pub fn bytes_per_line(&self) -> usize {
        16
    }

    /// 是否禁用颜色（固定为false，即启用颜色）
    pub fn no_color(&self) -> bool {
        false
    }
}
