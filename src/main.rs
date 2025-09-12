//! PCAP 文件查看器主程序

mod app;
mod cli;
mod core;

use app::error::types::Result;
use app::logging::setup::init_logging;

fn main() -> Result<()> {
    // 初始化日志系统
    init_logging();

    // 运行命令行界面
    cli::run_cli()
}
