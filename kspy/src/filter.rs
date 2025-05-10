use aya::{maps::HashMap, Ebpf};
use log::error;

pub fn init_pid_filter(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let pids: Vec<i32> = vec![];
    let mut target_pids_map: HashMap<_, i32, u8> =
        HashMap::try_from(ebpf.map_mut("TARGET_PIDS").unwrap())?;
    if pids.is_empty() {
        target_pids_map.insert(i32::MIN, 0, 0).map_err(|e| {
            error!("target_pids_map insert i32::MIN failed: {e}");
            e
        })?;
    } else {
        for pid in pids {
            target_pids_map.insert(pid, 0, 0).map_err(|e| {
                error!("insert {pid} failed: {e}");
                e
            })?;
        }
    }
    Ok(())
}

pub fn filter_path(path: String) -> bool {
    if path.contains("php_wbs") {
        return true;
    }
    false
}
