use std::{fs, os::unix::fs::MetadataExt};

pub fn find_path_by_inode(pid: i32, target_inode: u64) -> Option<String> {
    let fd_path = format!("/proc/{}/fd", pid);
    let entries = fs::read_dir(&fd_path).ok()?;

    for entry in entries.flatten() {
        let path = entry.path();
        if let Ok(metadata) = fs::metadata(&path) {
            let inode = metadata.ino();
            if inode == target_inode {
                // 找到 inode 匹配的 fd
                if let Ok(real_path) = fs::read_link(&path) {
                    return Some(real_path.to_string_lossy().to_string());
                }
            }
        }

        // fallback: stat(fd) 指向的文件
        if let Ok(real_path) = fs::read_link(&path) {
            if let Ok(metadata) = fs::metadata(&real_path) {
                let inode = metadata.ino();
                if inode == target_inode {
                    return Some(real_path.to_string_lossy().to_string());
                }
            }
        }
    }

    None
}
