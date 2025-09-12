//! 错误类型定义

use thiserror::Error;

/// PCAP 查看器错误类型
#[derive(Error, Debug)]
pub enum PcapViewerError {
    #[error("Invalid file format: {0}")]
    InvalidFormat(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Parse error: {0}")]
    ParseError(String),
}

/// 应用程序通用结果类型
pub type Result<T> = anyhow::Result<T>;