//! 终端管理模块

use crate::app::error::types::Result;
use crossterm::{
    cursor::{Hide, Show},
    execute,
    terminal::{self, Clear, ClearType},
};
use std::io;

/// 终端管理器
pub struct TerminalManager {
    is_raw_mode: bool,
}

impl TerminalManager {
    /// 创建新的终端管理器
    pub fn new() -> Self {
        Self { is_raw_mode: false }
    }

    /// 进入原始模式
    pub fn enter_raw_mode(&mut self) -> Result<()> {
        if !self.is_raw_mode {
            terminal::enable_raw_mode()?;
            execute!(io::stdout(), Hide)?;
            self.is_raw_mode = true;
        }
        Ok(())
    }

    /// 退出原始模式
    pub fn exit_raw_mode(&mut self) -> Result<()> {
        if self.is_raw_mode {
            terminal::disable_raw_mode()?;
            execute!(io::stdout(), Show)?;
            self.is_raw_mode = false;
        }
        Ok(())
    }

    /// 清空屏幕
    pub fn clear_screen(&self) -> Result<()> {
        execute!(io::stdout(), Clear(ClearType::All))?;
        Ok(())
    }

    /// 获取终端尺寸
    pub fn get_size(&self) -> (usize, usize) {
        terminal::size()
            .map(|(w, h)| (w as usize, h as usize))
            .unwrap_or((80, 24))
    }

    /// 计算可用的显示行数（减去帮助信息占用的行数）
    pub fn calculate_display_lines(
        &self,
        reserved_lines: usize,
    ) -> usize {
        let (_, height) = self.get_size();
        height.saturating_sub(reserved_lines)
    }
}

impl Drop for TerminalManager {
    fn drop(&mut self) {
        let _ = self.exit_raw_mode();
    }
}
