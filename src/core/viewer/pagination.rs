//! 分页逻辑模块

/// 分页状态
#[derive(Debug, Clone)]
pub struct PaginationState {
    lines_per_page: usize,
    display_start_line: usize,
    total_lines: usize,
}

impl PaginationState {
    /// 创建新的分页状态
    pub fn new(
        lines_per_page: usize,
        total_lines: usize,
    ) -> Self {
        Self {
            lines_per_page,
            display_start_line: 0,
            total_lines,
        }
    }

    /// 获取当前显示的起始行
    pub fn display_start_line(&self) -> usize {
        self.display_start_line
    }

    /// 获取每页行数
    pub fn lines_per_page(&self) -> usize {
        self.lines_per_page
    }

    /// 获取总行数
    pub fn total_lines(&self) -> usize {
        self.total_lines
    }

    /// 获取当前页码（从1开始）
    pub fn current_page(&self) -> usize {
        (self.display_start_line / self.lines_per_page) + 1
    }

    /// 获取总页数
    pub fn total_pages(&self) -> usize {
        self.total_lines.div_ceil(self.lines_per_page)
    }

    /// 向上滚动
    pub fn scroll_up(&mut self) {
        if self.display_start_line > 0 {
            self.display_start_line -= 1;
        }
    }

    /// 向下滚动
    pub fn scroll_down(&mut self) {
        let max_start_line = self
            .total_lines
            .saturating_sub(self.lines_per_page);
        if self.display_start_line < max_start_line {
            self.display_start_line += 1;
        }
    }

    /// 上一页
    pub fn page_up(&mut self) {
        self.display_start_line = self
            .display_start_line
            .saturating_sub(self.lines_per_page);
    }

    /// 下一页
    pub fn page_down(&mut self) {
        let max_start_line = self
            .total_lines
            .saturating_sub(self.lines_per_page);
        self.display_start_line = (self.display_start_line
            + self.lines_per_page)
            .min(max_start_line);
    }

    /// 跳转到第一页
    pub fn go_to_first_page(&mut self) {
        self.display_start_line = 0;
    }

    /// 跳转到最后一页
    pub fn go_to_last_page(&mut self) {
        self.display_start_line = self
            .total_lines
            .saturating_sub(self.lines_per_page);
    }

    /// 更新每页行数
    pub fn update_lines_per_page(
        &mut self,
        lines_per_page: usize,
    ) {
        self.lines_per_page = lines_per_page;
        // 重新计算当前页位置，确保不超出范围
        let max_start_line = self
            .total_lines
            .saturating_sub(self.lines_per_page);
        self.display_start_line =
            self.display_start_line.min(max_start_line);
    }
}
