//! 分页逻辑模块

/// 分页状态
#[derive(Debug, Clone)]
pub struct PaginationState {
    pub lines_per_page: usize,
    pub display_start_line: usize,
    pub total_lines: usize,
}

impl PaginationState {
    /// 创建新的分页状态
    pub fn new(lines_per_page: usize, total_lines: usize) -> Self {
        Self {
            lines_per_page,
            display_start_line: 0,
            total_lines,
        }
    }

    /// 向上滚动
    pub fn scroll_up(&mut self) {
        if self.display_start_line > 0 {
            self.display_start_line -= 1;
        }
    }

    /// 向下滚动
    pub fn scroll_down(&mut self) {
        let max_start_line = self.total_lines.saturating_sub(self.lines_per_page);
        if self.display_start_line < max_start_line {
            self.display_start_line += 1;
        }
    }

    /// 上一页
    pub fn page_up(&mut self) {
        self.display_start_line = self.display_start_line.saturating_sub(self.lines_per_page);
    }

    /// 下一页
    pub fn page_down(&mut self) {
        let max_start_line = self.total_lines.saturating_sub(self.lines_per_page);
        self.display_start_line = (self.display_start_line + self.lines_per_page).min(max_start_line);
    }

    /// 跳转到第一页
    pub fn go_to_first_page(&mut self) {
        self.display_start_line = 0;
    }

    /// 跳转到最后一页
    pub fn go_to_last_page(&mut self) {
        self.display_start_line = self.total_lines.saturating_sub(self.lines_per_page);
    }

    /// 更新每页行数
    pub fn update_lines_per_page(&mut self, lines_per_page: usize) {
        self.lines_per_page = lines_per_page;
        // 重新计算当前页位置，确保不超出范围
        let max_start_line = self.total_lines.saturating_sub(self.lines_per_page);
        self.display_start_line = self.display_start_line.min(max_start_line);
    }

    /// 获取当前页的行范围
    pub fn get_current_page_range(&self) -> (usize, usize) {
        let start = self.display_start_line;
        let end = (start + self.lines_per_page).min(self.total_lines);
        (start, end)
    }
}
