//! 命令行参数定义

use clap::Parser;
use std::path::PathBuf;

/// PCAP 文件查看器 - 支持自定义PCAP格式的十六进制查看工具
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct CliArgs {
    /// PCAP 文件路径
    #[arg(short, long, value_name = "FILE")]
    pub file_path: PathBuf,

    /// 每行显示的字节数 (默认: 16)
    #[arg(
        short = 'b',
        long = "bytes",
        default_value = "16"
    )]
    pub bytes_per_line: usize,

    /// 显示的行数 (默认: 显示全部)
    #[arg(short = 'n', long = "lines")]
    pub max_lines: Option<usize>,

    /// 从指定偏移量开始显示 (默认: 0)
    #[arg(
        short = 'o',
        long = "offset",
        default_value = "0"
    )]
    pub offset: usize,

    /// 启用颜色输出 (默认: 启用)
    #[arg(long = "no-color")]
    pub no_color: bool,

    /// 详细模式 - 显示更多解析信息
    #[arg(short, long)]
    pub verbose: bool,
}
