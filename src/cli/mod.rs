//! 命令行界面模块

pub mod args;
pub mod hex_viewer;

use clap::Parser;
use colored::*;

use crate::app::error::types::Result;

use self::args::CliArgs;
use self::hex_viewer::HexViewer;
use crate::core::pcap::parser::PcapParser;

/// 运行命令行界面
pub fn run_cli() -> Result<()> {
    let args = CliArgs::parse();

    // 检查文件是否存在
    if !args.file_path.exists() {
        eprintln!(
            "{} 文件不存在: {}",
            "错误".red().bold(),
            args.file_path.display()
        );
        std::process::exit(1);
    }

    // 创建 PCAP 解析器
    let parser = PcapParser::new(&args.file_path)?;

    // 创建十六进制查看器
    let mut viewer = HexViewer::new(parser, args)?;

    // 运行查看器
    viewer.run()
}
