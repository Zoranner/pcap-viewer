//! 日志系统初始化

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// 初始化日志系统
pub fn init_logging() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pcap_viewer=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}