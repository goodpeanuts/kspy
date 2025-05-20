use aya::{
    maps::{perf::PerfBufferError, AsyncPerfEventArray, ProgramArray},
    programs::KProbe,
    util::online_cpus,
};
use bytes::BytesMut;
use kspy::filter::{self, init_pid_filter};
use kspy_common::WriteEvent;
#[rustfmt::skip]
#[allow(unused_imports)]
use log::{debug, warn, error, info};
#[cfg(feature = "webshell-detect")]
use kspy::client::{send_request, setup_connection};
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

    let mut tail_call_map = ProgramArray::try_from(ebpf.take_map("JUMP_TABLE").unwrap())?;

    let prg_list = ["hook_path_reso"];

    for (i, prg) in prg_list.iter().enumerate() {
        {
            let program: &mut KProbe = ebpf.program_mut(prg).unwrap().try_into()?;
            program.load()?;
            let fd = program.fd().unwrap();
            tail_call_map.set(i as u32, fd, 0)?;
        }
    }

    // let btf = Btf::from_sys_fs().context("BTF from sysfs")?;
    // let program: &mut FEntry = ebpf.program_mut("ff").unwrap().try_into()?;
    // program.load("filp_close", &btf)?;
    // program.attach()?;

    // init_pid_filter(&mut ebpf)?;

    init_pid_filter(&mut ebpf).map_err(|e| {
        error!("init_pid_filter failed: {e}");
        e
    })?;

    #[cfg(feature = "webshell-detect")]
    let client = setup_connection().await?;

    let mut perf_array = AsyncPerfEventArray::try_from(ebpf.take_map("PERF_VFS_WRITE").unwrap())?;

    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        // open a separate perf buffer for each cpu
        let mut buf = perf_array.open(cpu_id, None)?;
        let client = client.clone();
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

                    let path = normalize_and_reverse_path(&t.path);
                    if !filter::filter_path(path.clone()) {
                        continue;
                    }

                    // 2. 打开文件发送信息
                    #[cfg(feature = "webshell-detect")]
                    if let Err(e) = send_request(path.clone(), &client).await {
                        error!("Failed to send file: {}", e);
                    }

                    info!("events: {:?}", path);
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

fn normalize_and_reverse_path(raw: &[u8]) -> String {
    use std::str::from_utf8_unchecked;
    let s = unsafe { from_utf8_unchecked(raw) }
        .split('\0')
        .next()
        .unwrap_or("");

    let s = s.trim_end_matches('/');

    let components: Vec<&str> = s.split('/').filter(|part| !part.is_empty()).collect();

    let reversed = components.into_iter().rev().collect::<Vec<_>>().join("/");

    format!("/{}", reversed)
}
