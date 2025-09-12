//! 键盘输入处理

use crossterm::event::KeyCode;
use std::time::Instant;

/// 键盘输入处理器
pub struct KeyboardHandler {
    last_key_time: Instant,
    last_key_code: Option<KeyCode>,
    debounce_duration_ms: u64,
}

impl KeyboardHandler {
    /// 创建新的键盘处理器
    pub fn new(debounce_duration_ms: u64) -> Self {
        Self {
            last_key_time: Instant::now(),
            last_key_code: None,
            debounce_duration_ms,
        }
    }

    /// 创建默认的键盘处理器（150ms 防抖）
    pub fn default() -> Self {
        Self::new(150)
    }

    /// 判断是否应该处理按键（防抖处理）
    pub fn should_process_key(
        &mut self,
        code: &KeyCode,
    ) -> bool {
        let now = Instant::now();
        let time_since_last =
            now.duration_since(self.last_key_time);

        // 检查是否是同一个键
        let is_same_key =
            self.last_key_code.as_ref() == Some(code);

        // 防抖逻辑：同一个键必须间隔指定时间
        if is_same_key
            && time_since_last.as_millis()
                < self.debounce_duration_ms as u128
        {
            return false;
        }

        // 更新状态
        self.last_key_code = Some(*code);
        self.last_key_time = now;

        true
    }
}
