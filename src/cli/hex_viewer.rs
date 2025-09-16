//! 十六进制查看器

use chrono::DateTime;
use colored::*;
use crossterm::event::{self, Event, KeyCode, KeyEvent};
use std::io::{self, Write};

use crate::app::error::types::Result;
use crate::cli::args::CliArgs;
use crate::core::input::keyboard::KeyboardHandler;
use crate::core::pcap::parser::{
    DataPacket, PcapFileHeader, PcapParser,
};
use crate::core::viewer::pagination::PaginationState;
use crate::core::viewer::terminal::TerminalManager;

/// 十六进制查看器
pub struct HexViewer {
    parser: PcapParser,
    args: CliArgs,
    file_data: Vec<u8>,
    // 模块化组件
    terminal_manager: TerminalManager,
    keyboard_handler: KeyboardHandler,
    pagination: PaginationState,
    // 状态管理
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

        // 创建组件
        let terminal_manager = TerminalManager::new();
        let keyboard_handler = KeyboardHandler::default();

        // 计算分页信息
        let lines_per_page =
            terminal_manager.calculate_display_lines(6); // 减去帮助信息占用的行数
        let total_lines =
            file_data.len().div_ceil(args.bytes_per_line());
        let pagination = PaginationState::new(
            lines_per_page,
            total_lines,
        );

        Ok(Self {
            parser,
            args,
            file_data,
            terminal_manager,
            keyboard_handler,
            pagination,
            last_display_start_line: usize::MAX, // 初始值设为最大值，确保第一次显示
        })
    }

    /// 运行查看器
    pub fn run(&mut self) -> Result<()> {
        if self.args.no_color() {
            colored::control::set_override(false);
        }

        // 进入交互模式
        self.interactive_mode()?;

        Ok(())
    }

    /// 交互模式
    fn interactive_mode(&mut self) -> Result<()> {
        // 启用原始模式
        self.terminal_manager.enter_raw_mode()?;

        // 初始显示
        self.terminal_manager.clear_screen()?;
        let _ = self.update_terminal_size()?; // 忽略返回值，初始化时总是需要显示
        self.display_current_page()?;
        self.display_help()?;
        // 确保初始显示内容已刷新到终端
        io::stdout().flush()?;

        loop {
            // 更新终端尺寸
            let size_changed =
                self.update_terminal_size()?;

            // 检查是否需要重绘
            let needs_redraw = size_changed
                || self.pagination.display_start_line()
                    != self.last_display_start_line;

            if needs_redraw {
                // 只有在需要时才重绘
                self.terminal_manager.clear_screen()?;
                self.display_current_page()?;
                self.display_help()?;
                // 确保所有输出都已刷新到终端
                io::stdout().flush()?;
                self.last_display_start_line =
                    self.pagination.display_start_line();
            }

            // 等待用户输入
            match event::read()? {
                Event::Key(KeyEvent {
                    code,
                    modifiers,
                    ..
                }) => {
                    // 使用键盘处理器进行防抖
                    if !self
                        .keyboard_handler
                        .should_process_key(&code)
                    {
                        continue;
                    }

                    match (code, modifiers) {
                        (KeyCode::Esc, _)
                        | (KeyCode::Char('q'), _) => {
                            break;
                        }
                        (KeyCode::Up, _) => {
                            self.pagination.scroll_up();
                        }
                        (KeyCode::Down, _) => {
                            self.pagination.scroll_down();
                        }
                        (KeyCode::Left, _) => {
                            self.pagination.page_up();
                        }
                        (KeyCode::Right, _) => {
                            self.pagination.page_down();
                        }
                        (KeyCode::Home, _) => {
                            self.pagination
                                .go_to_first_page();
                        }
                        (KeyCode::End, _) => {
                            self.pagination
                                .go_to_last_page();
                        }
                        (KeyCode::Char('r'), _) => {
                            // 刷新终端尺寸，强制重绘
                            let _ = self
                                .update_terminal_size()?;
                            self.last_display_start_line =
                                usize::MAX; // 强制重绘
                        }
                        _ => {}
                    }
                }
                Event::Mouse(_) => {
                    // 忽略所有鼠标事件（包括滚轮滚动）
                    continue;
                }
                _ => {
                    // 忽略其他事件
                    continue;
                }
            }
        }

        // 恢复终端（由 TerminalManager 的 Drop trait 自动处理）

        Ok(())
    }

    /// 更新终端尺寸
    fn update_terminal_size(&mut self) -> Result<bool> {
        // 重新计算分页信息
        let new_lines_per_page = self
            .terminal_manager
            .calculate_display_lines(6);
        let size_changed = new_lines_per_page
            != self.pagination.lines_per_page();

        if size_changed {
            // 更新分页信息
            self.pagination
                .update_lines_per_page(new_lines_per_page);
        }

        Ok(size_changed)
    }

    /// 显示当前页
    fn display_current_page(&self) -> Result<()> {
        // 从显示起始行开始，绘制 n 行
        let start_offset =
            self.pagination.display_start_line()
                * self.args.bytes_per_line();

        if start_offset >= self.file_data.len() {
            return Ok(());
        }

        let mut current_offset = start_offset;
        let mut lines_displayed = 0;

        while lines_displayed
            < self.pagination.lines_per_page()
        {
            if current_offset >= self.file_data.len() {
                break;
            }

            // 计算当前行的数据
            let line_end = std::cmp::min(
                current_offset + self.args.bytes_per_line(),
                self.file_data.len(),
            );
            let line_data =
                &self.file_data[current_offset..line_end];

            // 构建完整的行输出
            let mut line_output = String::new();

            // 添加地址偏移
            line_output.push_str(&format!(
                "{:08X}: ",
                current_offset
            ));

            // 添加十六进制数据
            line_output.push_str(&self.format_hex_line(
                line_data,
                current_offset,
            )?);

            // 添加解析信息分隔符和内容
            line_output.push('|');
            line_output.push_str(&self.format_parsed_info(
                line_data,
                current_offset,
            ));

            // 输出完整的一行（在原始模式下使用显式的\r\n）
            print!("{}\r\n", line_output);

            current_offset = line_end;
            lines_displayed += 1;
        }

        // 刷新输出缓冲区
        io::stdout().flush()?;
        Ok(())
    }

    /// 显示帮助信息
    fn display_help(&self) -> Result<()> {
        let current_page = self.pagination.current_page();
        let total_pages = self.pagination.total_pages();

        print!("\r\n");
        print!("{}\r\n", "=".repeat(80));
        print!(
            "{}\r\n",
            format!(
                "第 {} 行 / 共 {} 行 (第 {} 页 / 共 {} 页)",
                self.pagination.display_start_line() + 1,
                self.pagination.total_lines(),
                current_page,
                total_pages
            )
            .bright_white()
            .bold()
        );
        print!("{}\r\n", "导航: ↑↓ 逐行滚动 | ←→ 翻页 | Home/End 首页/末页 | r 刷新 | ESC/q 退出".bright_black());
        print!("{}\r\n", "=".repeat(80));

        // 刷新输出缓冲区
        io::stdout().flush()?;
        Ok(())
    }

    /// 格式化十六进制行数据（带颜色标记）
    fn format_hex_line(
        &self,
        data: &[u8],
        offset: usize,
    ) -> Result<String> {
        let mut output = String::new();

        // 简化逻辑：直接按字节顺序显示，根据位置应用颜色
        for i in 0..self.args.bytes_per_line() {
            if i < data.len() {
                let byte = data[i];
                let current_offset = offset + i;

                // 根据字节位置确定颜色
                let color_type = self
                    .get_byte_color_type(current_offset);
                let formatted_byte = match color_type {
                    ByteColorType::FileHeader => {
                        // 文件头区域 - 紫色背景
                        format!("{:02X} ", byte)
                            .on_bright_magenta()
                            .bright_white()
                            .bold()
                            .to_string()
                    }
                    ByteColorType::PacketHeader => {
                        // 数据包头区域 - 青色背景
                        format!("{:02X} ", byte)
                            .on_bright_cyan()
                            .black()
                            .bold()
                            .to_string()
                    }
                    ByteColorType::PacketData => {
                        // 数据包体区域 - 黄色背景
                        format!("{:02X} ", byte)
                            .on_bright_yellow()
                            .black()
                            .bold()
                            .to_string()
                    }
                    ByteColorType::Unknown => {
                        // 未知区域 - 无颜色
                        format!("{:02X} ", byte)
                    }
                };

                output.push_str(&formatted_byte);
            } else {
                // 填充空白
                output.push_str("   ");
            }
        }

        Ok(output)
    }

    /// 格式化解析信息
    fn format_parsed_info(
        &self,
        data: &[u8],
        offset: usize,
    ) -> String {
        // 文件头区域 (0-15)
        if offset < 16 {
            self.format_file_header_info(data, offset)
        }
        // 数据包区域
        else if let Some(packet_info) =
            self.find_packet_header_in_line(offset)
        {
            self.format_packet_info(
                data,
                offset,
                &packet_info,
            )
        }
        // 其他区域 - 解析失败时不显示原始数据
        else {
            String::new()
        }
    }

    /// 格式化文件头解析信息
    fn format_file_header_info(
        &self,
        data: &[u8],
        offset: usize,
    ) -> String {
        if data.len() < 16 {
            return self.format_raw_data(data);
        }

        // 如果是文件头的第一行，显示所有字段
        if offset == 0 {
            let header_values: PcapFileHeader =
                if let Some(h) = self.parser.file_header() {
                    h.clone()
                } else {
                    PcapFileHeader {
                        magic_number: u32::from_le_bytes([
                            data[0], data[1], data[2],
                            data[3],
                        ]),
                        major_version: u16::from_le_bytes(
                            [data[4], data[5]],
                        ),
                        minor_version: u16::from_le_bytes(
                            [data[6], data[7]],
                        ),
                        timezone_offset: u32::from_le_bytes(
                            [
                                data[8], data[9], data[10],
                                data[11],
                            ],
                        ),
                        timestamp_accuracy:
                            u32::from_le_bytes([
                                data[12], data[13],
                                data[14], data[15],
                            ]),
                    }
                };

            let is_magic_invalid =
                header_values.magic_number != 0xD4C3B2A1;
            let is_version_invalid =
                !(header_values.major_version == 2
                    && header_values.minor_version == 4);

            let magic_text = format!(
                "0x{:08X}",
                header_values.magic_number
            );
            let magic_out = if is_magic_invalid {
                magic_text.bright_red().bold().to_string()
            } else {
                magic_text.bright_green().to_string()
            };

            let ver_text = format!(
                "{}.{}",
                header_values.major_version,
                header_values.minor_version
            );
            let ver_out = if is_version_invalid {
                ver_text.bright_red().bold().to_string()
            } else {
                ver_text.bright_green().to_string()
            };

            format!(
                " MAGIC: {} VER: {} TZ: {} TS_ACC: {}",
                magic_out,
                ver_out,
                header_values.timezone_offset,
                header_values.timestamp_accuracy
            )
        } else {
            // 其他情况不显示任何内容
            String::new()
        }
    }

    /// 格式化数据包解析信息
    fn format_packet_info(
        &self,
        data: &[u8],
        offset: usize,
        packet_info: &PacketInfo,
    ) -> String {
        let packet_start = packet_info.start;
        let header_end = packet_start + 16;
        let data_start = header_end;

        // 检查当前行是否与数据包头区域有重叠
        let line_end = offset + data.len();
        if (offset >= packet_start && offset < header_end)
            || (packet_start >= offset
                && packet_start < line_end)
        {
            // 数据包头区域 - 检查当前行是否包含数据包头的开始部分
            let line_end = offset + data.len();

            // 如果当前行包含时间戳的开始位置（前8字节），显示完整的时间戳信息
            if packet_start >= offset
                && packet_start < line_end
            {
                let seconds = packet_info
                    .packet
                    .header
                    .timestamp_seconds;
                let nanoseconds = packet_info
                    .packet
                    .header
                    .timestamp_nanoseconds;
                let (time_text, is_time_valid) =
                    Self::format_packet_time(
                        seconds,
                        nanoseconds,
                    );

                // 统一在这里处理所有颜色
                let colored_time = if is_time_valid {
                    time_text.bright_green().to_string()
                } else {
                    time_text
                        .bright_red()
                        .bold()
                        .to_string()
                };

                // 数据包长度通常都是有效的，显示为绿色
                let colored_len = format!(
                    "{}",
                    packet_info.packet.header.packet_length
                )
                .bright_green()
                .to_string();

                format!(
                    " TIME: {} LEN: {} CRC: 0x{:08X}",
                    colored_time,
                    colored_len,
                    packet_info.packet.header.checksum
                )
            }
            // 如果当前行包含数据包头的后半部分（长度和校验和），不显示额外信息
            else {
                String::new()
            }
        } else if offset >= data_start {
            // 数据包体区域 - 数据包体区域不显示额外信息
            String::new()
        } else {
            String::new()
        }
    }

    /// 格式化数据包时间戳为 YYYY-MM-dd HH:mm:ss.ns，返回(时间字符串, 是否有效)
    fn format_packet_time(
        seconds: u32,
        nanoseconds: u32,
    ) -> (String, bool) {
        if let Some(dt) = DateTime::from_timestamp(
            seconds as i64,
            nanoseconds,
        ) {
            let base =
                dt.format("%Y-%m-%dT%H:%M:%S").to_string();
            let time_str =
                format!("{}.{:09}", base, nanoseconds);
            (time_str, true) // 有效时间戳
        } else {
            let time_str = format!(
                "INVALID_TS({},{})",
                seconds, nanoseconds
            );
            (time_str, false) // 无效时间戳
        }
    }

    /// 格式化原始数据
    fn format_raw_data(&self, data: &[u8]) -> String {
        let mut output = String::new();
        for &byte in data {
            let ch = if (32..=126).contains(&byte) {
                byte as char
            } else {
                '.'
            };
            output.push(ch);
        }
        output
    }

    /// 查找指定行是否包含数据包头开始位置（用于时间戳显示）
    fn find_packet_header_in_line(
        &self,
        line_offset: usize,
    ) -> Option<PacketInfo> {
        let mut current_offset = 16; // 跳过文件头
        let line_end = line_offset + 16; // 当前行结束位置

        for packet in self.parser.packets() {
            let packet_start = current_offset;
            let packet_header_size = 16;
            let packet_data_size =
                packet.header.packet_length as usize;
            let packet_total_size =
                packet_header_size + packet_data_size;

            // 检查数据包头是否在当前行内
            if packet_start >= line_offset
                && packet_start < line_end
            {
                return Some(PacketInfo {
                    start: packet_start,
                    packet: packet.clone(),
                });
            }

            current_offset += packet_total_size;
        }

        None
    }

    /// 获取指定字节位置的颜色类型（用于颜色标记）
    fn get_byte_color_type(
        &self,
        byte_offset: usize,
    ) -> ByteColorType {
        // 文件头区域
        if byte_offset < 16 {
            return ByteColorType::FileHeader;
        }

        let mut current_offset = 16; // 跳过文件头

        for packet in self.parser.packets() {
            let packet_start = current_offset;
            let packet_header_end = packet_start + 16;
            let packet_data_end = packet_header_end
                + packet.header.packet_length as usize;

            if byte_offset >= packet_start
                && byte_offset < packet_header_end
            {
                return ByteColorType::PacketHeader;
            } else if byte_offset >= packet_header_end
                && byte_offset < packet_data_end
            {
                return ByteColorType::PacketData;
            }

            current_offset = packet_data_end;
        }

        ByteColorType::Unknown
    }
}

/// 数据包信息
#[derive(Debug, Clone)]
struct PacketInfo {
    start: usize,
    packet: DataPacket,
}

/// 字节颜色类型
#[derive(Debug, Clone, PartialEq)]
enum ByteColorType {
    FileHeader,   // 文件头 - 紫色
    PacketHeader, // 数据包头 - 青色
    PacketData,   // 数据包数据 - 黄色
    Unknown,      // 未知区域 - 无颜色
}
