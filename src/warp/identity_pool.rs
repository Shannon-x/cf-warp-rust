//! 身份池 —— 一组预注册好的 WARP 账号；当当前身份被限流或封禁、恢复阶梯走
//! 到顶之后，supervisor 会从这里取下一个轮换上去。每个文件的格式与
//! `data/account.json` 完全一致。

use crate::error::Result;
use std::path::{Path, PathBuf};
use tracing::info;

pub struct IdentityPool {
    files: Vec<PathBuf>,
    next_idx: usize,
}

impl IdentityPool {
    /// 列出 `<data_dir>/identities/*.json`（按字典序排序）。目录不存在时返回
    /// 空池，不是错误。
    pub fn load(data_dir: &Path) -> Result<Self> {
        let dir = data_dir.join("identities");
        let mut files: Vec<PathBuf> = if dir.exists() {
            std::fs::read_dir(&dir)?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
                .collect()
        } else {
            Vec::new()
        };
        files.sort();
        info!(count = files.len(), path = %dir.display(), "identity pool loaded");
        Ok(Self { files, next_idx: 0 })
    }

    /// 返回下一个身份文件（round-robin）。空池返回 `None`。
    pub fn next_identity(&mut self) -> Option<PathBuf> {
        if self.files.is_empty() {
            return None;
        }
        let idx = self.next_idx % self.files.len();
        self.next_idx = self.next_idx.wrapping_add(1);
        Some(self.files[idx].clone())
    }
}
