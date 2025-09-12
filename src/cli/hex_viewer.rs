//! 十六进制查看器

use colored::*;
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEvent},
    execute,
    terminal::{self, Clear, ClearType},
};

use std::io;

use crate::app::error::types::Result;
use crate::cli::args::CliArgs;
use crate::core::pcap::parser::{PcapParser, PacketInfo};
use crate::core::viewer::display_utils;

/// 十六进制查看器
pub struct HexViewer {
    parser: PcapParser,
    args: CliArgs,
    bytes_per_line: usize,
    file_data: Vec<u8>,
    // 分页相关字段
    lines_per_page: usize, // 每页显示的行数 n
    display_start_line: usize, // 显示窗口的起始行 i
    last_key_time: std::time::Instant, // 上次按键时间，用于防抖
    last_key_code: Option<KeyCode>,    // 上次按下的键
    key_repeat_count: u32,             // 连续按键计数
    last_display_start_line: usize, // 上次显示的起始行，用于检测是否需要重绘
}

impl HexViewer {
    /// 创建新的十六进制查看器
    pub fn new(
        parser: PcapParser,
        args: CliArgs,
    ) -> Result<Self> {
        // 读取整个文件到内存
        let file_data = std::fs::read(&args.file_path)?;

        // 获取终端尺寸
        let (_, terminal_height) = terminal::size()
            .map(|(w, h)| (w as usize, h as usize))
            .unwrap_or((80, 24)); // 默认尺寸

        // 计算分页信息 - 动态调整显示区域
        let lines_per_page =
            terminal_height.saturating_sub(6); // 减去帮助信息占用的行数

        Ok(Self {
            parser,
            args: args.clone(),
            bytes_per_line: args.bytes_per_line,
            file_data,
            lines_per_page,
            display_start_line: 0,
            last_key_time: std::time::Instant::now(),
            last_key_code: None,
            key_repeat_count: 0,
            last_display_start_line: usize::MAX, // 初始值设为最大值，确保第一次显示
        })
    }

    /// 运行查看器
    pub fn run(&mut self) -> Result<()> {
        if self.args.no_color {
            colored::control::set_override(false);
        }

        // 进入交互模式
        self.interactive_mode()?;

        Ok(())
    }

    /// 交互模式
    fn interactive_mode(&mut self) -> Result<()> {
        // 启用原始模式
        terminal::enable_raw_mode()?;
        execute!(io::stdout(), Hide)?;

        // 初始显示
        execute!(io::stdout(), Clear(ClearType::All))?;
        let _ = self.update_terminal_size()?; // 忽略返回值，初始化时总是需要显示
        self.display_current_page()?;
        self.display_help()?;

        loop {
            // 更新终端尺寸
            let size_changed =
                self.update_terminal_size()?;

            // 检查是否需要重绘
            let needs_redraw = size_changed
                || self.display_start_line
                    != self.last_display_start_line;

            if needs_redraw {
                // 只有在需要时才重绘
                execute!(
                    io::stdout(),
                    Clear(ClearType::All)
                )?;
                self.display_current_page()?;
                self.display_help()?;
                self.last_display_start_line =
                    self.display_start_line;
            }

            // 等待用户输入
            if let Event::Key(KeyEvent {
                code,
                modifiers,
                ..
            }) = event::read()?
            {
                // 改进的按键处理逻辑
                if !self.should_process_key(&code) {
                    continue;
                }

                match (code, modifiers) {
                    (KeyCode::Esc, _)
                    | (KeyCode::Char('q'), _) => {
                        break;
                    }
                    (KeyCode::Up, _) => {
                        self.scroll_up();
                    }
                    (KeyCode::Down, _) => {
                        self.scroll_down();
                    }
                    (KeyCode::Left, _) => {
                        self.page_up();
                    }
                    (KeyCode::Right, _) => {
                        self.page_down();
                    }
                    (KeyCode::Home, _) => {
                        self.go_to_first_page();
                    }
                    (KeyCode::End, _) => {
                        self.go_to_last_page();
                    }
                    (KeyCode::Char('r'), _) => {
                        // 刷新终端尺寸，强制重绘
                        let _ =
                            self.update_terminal_size()?;
                        self.last_display_start_line =
                            usize::MAX; // 强制重绘
                    }
                    _ => {}
                }
            }
        }

        // 恢复终端
        execute!(io::stdout(), Show)?;
        terminal::disable_raw_mode()?;

        Ok(())
    }

    /// 判断是否应该处理按键（简化的防抖处理）
    fn should_process_key(
        &mut self,
        code: &KeyCode,
    ) -> bool {
        let now = std::time::Instant::now();
        let time_since_last = now.duration_since(self.last_key_time);

        // 检查是否是同一个键
        let is_same_key = self.last_key_code.as_ref() == Some(code);

        // 简单的防抖逻辑：同一个键必须间隔至少150ms
        if is_same_key && time_since_last < std::time::Duration::from_millis(150) {
            return false;
        }

        // 更新状态
        self.last_key_code = Some(*code);
        self.last_key_time = now;
        
        // 重置计数器（保留字段以免破坏结构，但不使用复杂逻辑）
        self.key_repeat_count = 0;
        
        true
    }

    /// 更新终端尺寸
    fn update_terminal_size(&mut self) -> Result<bool> {
        let (_, terminal_height) = terminal::size()
            .map(|(w, h)| (w as usize, h as usize))
            .unwrap_or((80, 24)); // 默认尺寸

        // 重新计算分页信息
        let new_lines_per_page =
            terminal_height.saturating_sub(6); // 减去帮助信息占用的行数

        let size_changed =
            new_lines_per_page != self.lines_per_page;

        if size_changed {
            // 更新分页信息
            self.lines_per_page = new_lines_per_page;

            // 确保显示起始行不超出范围
            let total_lines = self
                .file_data
                .len()
                .div_ceil(self.bytes_per_line);
            let max_start_line = total_lines
                .saturating_sub(self.lines_per_page);
            if self.display_start_line > max_start_line {
                self.display_start_line = max_start_line;
            }
        }

        Ok(size_changed)
    }

    /// 显示当前页
    fn display_current_page(&self) -> Result<()> {
        // 从显示起始行开始，绘制 n 行
        let start_offset =
            self.display_start_line * self.bytes_per_line;

        if start_offset >= self.file_data.len() {
            return Ok(());
        }

        let mut current_offset = start_offset;
        let mut lines_displayed = 0;

        while lines_displayed < self.lines_per_page {
            if current_offset >= self.file_data.len() {
                break;
            }

            // 计算当前行的数据
            let line_end = std::cmp::min(
                current_offset + self.bytes_per_line,
                self.file_data.len(),
            );
            let line_data =
                &self.file_data[current_offset..line_end];

            // 显示地址偏移
            print!("{:08X}: ", current_offset);

            // 显示十六进制数据
            self.display_hex_line(
                line_data,
                current_offset,
            )?;

            // 显示解析信息
            print!("|");
            self.display_parsed_info(
                line_data,
                current_offset,
            );

            println!();

            current_offset = line_end;
            lines_displayed += 1;
        }

        Ok(())
    }

    /// 显示帮助信息
    fn display_help(&self) -> Result<()> {
        let total_lines = self
            .file_data
            .len()
            .div_ceil(self.bytes_per_line);
        let current_page = self.display_start_line
            / self.lines_per_page
            + 1;
        let total_pages =
            total_lines.div_ceil(self.lines_per_page);

        println!();
        println!("{}", "=".repeat(80).bright_blue());
        println!(
            "{}",
            format!(
                "第 {} 行 / 共 {} 行 (第 {} 页 / 共 {} 页)",
                self.display_start_line + 1,
                total_lines,
                current_page,
                total_pages
            )
            .bright_cyan()
        );
        println!("{}", "导航: ↑↓ 逐行滚动 | ←→ 翻页 | Home/End 首页/末页 | r 刷新 | ESC/q 退出".bright_yellow());
        println!("{}", "=".repeat(80).bright_blue());

        Ok(())
    }

    /// 向上滚动（逐行）
    fn scroll_up(&mut self) {
        if self.display_start_line > 0 {
            self.display_start_line -= 1;
        }
    }

    /// 向下滚动（逐行）
    fn scroll_down(&mut self) {
        let total_lines = self
            .file_data
            .len()
            .div_ceil(self.bytes_per_line);
        let max_start_line =
            total_lines.saturating_sub(self.lines_per_page);
        if self.display_start_line < max_start_line {
            self.display_start_line += 1;
        }
    }

    /// 上一页（跳转 n 行）
    fn page_up(&mut self) {
        if self.display_start_line >= self.lines_per_page {
            self.display_start_line -= self.lines_per_page;
        } else {
            self.display_start_line = 0;
        }
    }

    /// 下一页（跳转 n 行）
    fn page_down(&mut self) {
        let total_lines = self
            .file_data
            .len()
            .div_ceil(self.bytes_per_line);
        let max_start_line =
            total_lines.saturating_sub(self.lines_per_page);
        let new_start_line =
            self.display_start_line + self.lines_per_page;
        if new_start_line <= max_start_line {
            self.display_start_line = new_start_line;
        } else {
            self.display_start_line = max_start_line;
        }
    }

    /// 跳转到首页
    fn go_to_first_page(&mut self) {
        self.display_start_line = 0;
    }

    /// 跳转到末页
    fn go_to_last_page(&mut self) {
        let total_lines = self
            .file_data
            .len()
            .div_ceil(self.bytes_per_line);
        self.display_start_line =
            total_lines.saturating_sub(self.lines_per_page);
    }

    /// 显示十六进制行数据（带颜色标记）
    fn display_hex_line(
        &self,
        data: &[u8],
        offset: usize,
    ) -> Result<()> {
        let mut i = 0;

        // 文件头区域 (0-15) - 蓝色背景
        if offset < 16 {
            for &byte in data {
                if i < 16 {
                    print!(
                        "{}",
                        format!("{:02X} ", byte)
                            .on_blue()
                            .black()
                    );
                    i += 1;
                } else {
                    break;
                }
            }
            // 填充剩余空间
            while i < 16 {
                print!("   ");
                i += 1;
            }
            return Ok(());
        }

        // 数据包区域
        let mut current_offset = offset;
        let mut remaining_bytes = data.len();

        while remaining_bytes > 0 {
            // 查找当前偏移量对应的数据包
            if let Some(packet_info) =
                self.parser.find_packet_at_offset(current_offset)
            {
                let packet_start = packet_info.start;
                let packet_header_end = packet_start + 16;
                let packet_data_end = packet_header_end
                    + packet_info
                        .packet
                        .header
                        .packet_length
                        as usize;

                // 数据包头区域 (16字节) - 绿色背景
                if current_offset >= packet_start
                    && current_offset < packet_header_end
                {
                    let header_offset =
                        current_offset - packet_start;
                    let bytes_to_show = std::cmp::min(
                        16 - header_offset,
                        remaining_bytes,
                    );

                    for j in 0..bytes_to_show {
                        let byte = data[i + j];
                        print!(
                            "{}",
                            format!("{:02X} ", byte)
                                .on_green()
                                .black()
                        );
                    }

                    current_offset += bytes_to_show;
                    remaining_bytes -= bytes_to_show;
                    i += bytes_to_show;
                }
                // 数据包体区域 - 黄色背景
                else if current_offset
                    >= packet_header_end
                    && current_offset < packet_data_end
                {
                    let data_offset =
                        current_offset - packet_header_end;
                    let bytes_to_show = std::cmp::min(
                        packet_info
                            .packet
                            .header
                            .packet_length
                            as usize
                            - data_offset,
                        remaining_bytes,
                    );

                    for j in 0..bytes_to_show {
                        let byte = data[i + j];
                        print!(
                            "{}",
                            format!("{:02X} ", byte)
                                .on_yellow()
                                .black()
                        );
                    }

                    current_offset += bytes_to_show;
                    remaining_bytes -= bytes_to_show;
                    i += bytes_to_show;
                } else {
                    // 跳过到下一个数据包
                    current_offset = packet_data_end;
                }
            } else {
                // 没有找到对应的数据包，显示原始数据
                for j in 0..remaining_bytes {
                    let byte = data[i + j];
                    print!("{:02X} ", byte);
                }
                break;
            }
        }

        // 填充剩余空间
        while i < self.bytes_per_line {
            print!("   ");
            i += 1;
        }

        Ok(())
    }

    /// 显示解析信息
    fn display_parsed_info(
        &self,
        data: &[u8],
        offset: usize,
    ) {
        // 文件头区域 (0-15)
        if offset < 16 {
            self.display_file_header_info(data, offset);
        }
        // 数据包区域
        else if let Some(packet_info) =
            self.parser.find_packet_at_offset(offset)
        {
            self.display_packet_info(
                data,
                offset,
                &packet_info,
            );
        }
        // 其他区域
        else {
            self.display_raw_data(data);
        }
    }

    /// 显示文件头解析信息
    fn display_file_header_info(
        &self,
        data: &[u8],
        offset: usize,
    ) {
        if data.len() < 16 {
            self.display_raw_data(data);
            return;
        }

        // 如果是文件头的第一行，显示所有字段
        if offset == 0 {
            if let Some(header) = self.parser.file_header()
            {
                print!(" MAGIC: 0x{:08X} VER: {}.{} TZ: {} TS_ACC: {}",
                           header.magic_number, header.major_version, header.minor_version,
                           header.timezone_offset, header.timestamp_accuracy);
            } else {
                // 如果解析器中没有文件头，则手动解析
                if let Some(formatted) = display_utils::format_file_header_info(data) {
                    print!("{}", formatted);
                }
            }
        } else {
            // 其他情况显示原始数据
            self.display_raw_data(data);
        }
    }

    /// 显示数据包解析信息
    fn display_packet_info(
        &self,
        data: &[u8],
        offset: usize,
        packet_info: &PacketInfo,
    ) {
        let packet_start = packet_info.start;
        let header_end = packet_start + 16;
        let data_start = header_end;

        if offset >= packet_start && offset < header_end {
            // 数据包头区域 - 如果是包头的第一行，显示所有字段
            let header_offset = offset - packet_start;
            if data.len() >= 16 && header_offset == 0 {
                print!(
                    " TS: {} NS: {} LEN: {} CRC: 0x{:08X}",
                    packet_info
                        .packet
                        .header
                        .timestamp_seconds,
                    packet_info
                        .packet
                        .header
                        .timestamp_nanoseconds,
                    packet_info.packet.header.packet_length,
                    packet_info.packet.header.checksum
                );
            } else {
                self.display_raw_data(data);
            }
        } else if offset >= data_start {
            // 数据包体区域 - 显示数据包信息
            // 数据包体区域不显示额外信息
        } else {
            self.display_raw_data(data);
        }
    }

    /// 显示原始数据
    fn display_raw_data(&self, data: &[u8]) {
        let ascii_str = display_utils::display_raw_data_as_ascii(data);
        print!("{}", ascii_str);
    }

}