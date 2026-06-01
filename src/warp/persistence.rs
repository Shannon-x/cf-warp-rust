//! 一个小巧的原子 JSON 读写器，专门给 WARP 凭据文件用。
//!
//! 数据量小（一个账号大约 300 字节）且只有 supervisor 一个 writer，引入嵌入
//! 式 KV 完全没必要。写入流程：先写到同目录下的临时文件，fsync，再 rename 覆
//! 盖目标——POSIX 标准的原子替换模式。

use crate::error::{Error, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;
use tempfile::NamedTempFile;

pub fn load<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Io(e)),
    }
}

pub fn save<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| Error::other(format!("path has no parent: {}", path.display())))?;
    std::fs::create_dir_all(dir)?;

    let bytes = serde_json::to_vec_pretty(value)?;
    let mut tmp = NamedTempFile::new_in(dir)?;
    std::io::Write::write_all(&mut tmp, &bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| Error::Io(e.error))?;

    // Unix 下把权限锁到 0600，避免凭据被其他用户读取
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }

    Ok(())
}
