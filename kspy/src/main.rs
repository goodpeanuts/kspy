use aya::{
    maps::{perf::PerfBufferError, AsyncPerfEventArray},
    programs::KProbe,
    util::online_cpus,
};
use bytes::BytesMut;
use kspy_common::WriteEvent;
#[rustfmt::skip]
use log::{debug, warn, error, info};
use kspy::file::find_path_by_inode;
use tokio::{signal, task};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/kspy"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }
    let program: &mut KProbe = ebpf.program_mut("hook_vfs_write").unwrap().try_into()?;
    program.load()?;
    program.attach("vfs_write", 0)?;

    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("PERF_VFS_WRITE").unwrap())?;

    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        // open a separate perf buffer for each cpu
        let mut buf = perf_array.open(cpu_id, None)?;

        // process each perf buffer in a separate task
        #[allow(unreachable_code)]
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                // wait for events
                let events = buf.read_events(&mut buffers).await?;

                // events.read contains the number of events that have been read,
                // and is always <= buffers.len()
                for buf in buffers.iter_mut().take(events.read) {
                    // let buf = &mut buffers[i];
                    // process buf
                    let event = buf.as_ptr() as *const WriteEvent;
                    let t = unsafe { *event };
                    let pid = t.pid;
                    let inode = t.inode;
                    let filename = std::ffi::CStr::from_bytes_until_nul(&t.filename);
                    if let Ok(name) = filename {
                        let name = name.to_str().unwrap_or("invalid utf-8");
                        debug!("events: {:?}", name);
                        if let Some(path) = find_path_by_inode(pid, inode) {
                            info!("events: path: {}", path);
                        } else {
                            error!("[!] events: {name} path not found");
                        }
                    } else {
                        error!("events: invalid utf-8 in filename");
                    }
                }
            }

            Ok::<_, PerfBufferError>(())
        });
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
