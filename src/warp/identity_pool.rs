//! 身份池 —— 一组预注册好的 WARP 账号；当当前身份被限流或封禁、恢复阶梯走
//! 到顶之后，supervisor 会从这里取下一个轮换上去。每个文件的格式与
//! `data/account.json` 完全一致。

use crate::error::Result;
use std::path::{Path, PathBuf};
use tracing::info;

pub struct IdentityPool {
    dir: PathBuf,
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
        Ok(Self {
            dir,
            files,
            next_idx: 0,
        })
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
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

    /// 把选中的身份原子替换到 `<data_dir>/account.json`。
    pub fn activate(&self, data_dir: &Path, src: &Path) -> Result<()> {
        use std::io::Write;
        let bytes = std::fs::read(src)?;
        let dest = data_dir.join("account.json");
        let mut tmp = tempfile::NamedTempFile::new_in(data_dir)?;
        tmp.write_all(&bytes)?;
        tmp.as_file().sync_all()?;
        tmp.persist(&dest)
            .map_err(|e| crate::error::Error::Io(e.error))?;

        // Unix 下把权限锁到 0600，避免凭据被其他用户读取
        // —— 与 persistence::save 保持一致（见 src/warp/persistence.rs）
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&dest)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&dest, perms)?;
        }

        info!(src = %src.display(), dest = %dest.display(), "activated identity from pool");
        Ok(())
    }

    pub fn directory(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `activate` 写出的 `account.json` 在 Unix 下必须是 0600，
    /// 即使源池文件本身权限是宽松的（例如 0644，常见于用户手动 cp 进来的情况）。
    #[cfg(unix)]
    #[test]
    fn activate_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmpdir = tempfile::tempdir().expect("tempdir");
        let data_dir = tmpdir.path();
        let pool_dir = data_dir.join("identities");
        std::fs::create_dir_all(&pool_dir).unwrap();

        // 写一个权限 0644 的池身份文件
        let src = pool_dir.join("a.json");
        std::fs::write(&src, br#"{"private_key":"x"}"#).unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o644)).unwrap();

        let pool = IdentityPool::load(data_dir).expect("load pool");
        pool.activate(data_dir, &src).expect("activate ok");

        let dest = data_dir.join("account.json");
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "account.json 应被锁到 0600，实际 {:o}", mode);

        // 内容必须正确复制
        let copied = std::fs::read(&dest).unwrap();
        assert_eq!(copied, br#"{"private_key":"x"}"#);
    }

    /// 反复 activate 不同身份时，每次都应该重新落盘到 0600。
    #[cfg(unix)]
    #[test]
    fn activate_overwrite_keeps_0600() {
        use std::os::unix::fs::PermissionsExt;

        let tmpdir = tempfile::tempdir().unwrap();
        let data_dir = tmpdir.path();
        let pool_dir = data_dir.join("identities");
        std::fs::create_dir_all(&pool_dir).unwrap();

        let a = pool_dir.join("a.json");
        let b = pool_dir.join("b.json");
        std::fs::write(&a, b"{\"k\":1}").unwrap();
        std::fs::write(&b, b"{\"k\":2}").unwrap();
        std::fs::set_permissions(&b, std::fs::Permissions::from_mode(0o666)).unwrap();

        let pool = IdentityPool::load(data_dir).unwrap();
        pool.activate(data_dir, &a).unwrap();
        pool.activate(data_dir, &b).unwrap();

        let dest = data_dir.join("account.json");
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&dest).unwrap(), b"{\"k\":2}");
    }
}
