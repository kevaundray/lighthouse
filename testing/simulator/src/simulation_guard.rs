//! Reject native scheduling/network/entropy effects instead of silently escaping the model.

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};
use std::collections::BTreeMap;

/// Install only in the dedicated simulation process, after single-thread setup.
///
/// MadSim handles these effects in userspace. A missed dependency adaptation
/// raises SIGSYS, including when the caller would otherwise ignore an I/O error.
/// Filesystem operations remain synchronous real operations on disposable fixture
/// directories; this guard does not claim to simulate disk crash durability.
pub fn install() -> Result<(), String> {
    let forbidden = [
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_epoll_create,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_wait,
        libc::SYS_epoll_pwait,
        libc::SYS_epoll_pwait2,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_getrandom,
        libc::SYS_clock_gettime,
        libc::SYS_gettimeofday,
        libc::SYS_time,
        libc::SYS_nanosleep,
        libc::SYS_clock_nanosleep,
        libc::SYS_futex_waitv,
    ];
    let mut rules: BTreeMap<_, _> = forbidden
        .into_iter()
        .map(|number| (number, vec![]))
        .collect();
    let waiting_operations = [
        libc::FUTEX_WAIT,
        libc::FUTEX_WAIT_BITSET,
        libc::FUTEX_WAIT_REQUEUE_PI,
        libc::FUTEX_LOCK_PI,
        libc::FUTEX_LOCK_PI2,
    ];
    let waits = waiting_operations
        .into_iter()
        .map(|operation| {
            let condition = SeccompCondition::new(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(libc::FUTEX_CMD_MASK as u32 as u64),
                operation as u64,
            )
            .map_err(|error| format!("cannot construct native wait condition: {error}"))?;
            SeccompRule::new(vec![condition])
                .map_err(|error| format!("cannot construct native wait rule: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    rules.insert(libc::SYS_futex, waits);
    let architecture = std::env::consts::ARCH
        .try_into()
        .map_err(|error| format!("unsupported simulation guard architecture: {error}"))?;
    let filter: BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Trap,
        architecture,
    )
    .map_err(|error| format!("cannot construct simulation effect guard: {error}"))?
    .try_into()
    .map_err(|error| format!("cannot compile simulation effect guard: {error}"))?;
    seccompiler::apply_filter(&filter)
        .map_err(|error| format!("cannot install simulation effect guard: {error}"))
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::process::ExitStatusExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    #[test]
    fn rejects_uncontrolled_effects() {
        for effect in ["socket", "wait", "thread", "entropy", "clock"] {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "simulation_guard::tests::guard_child",
                    "--ignored",
                ])
                .env("LIGHTHOUSE_GUARD_TEST_EFFECT", effect)
                .stdout(Stdio::null())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("native {effect} escaped the guard and blocked");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            assert_eq!(
                status.signal(),
                Some(libc::SIGSYS),
                "native {effect}: {status}"
            );
        }
    }

    #[test]
    #[ignore = "subprocess-only: intentionally terminates with SIGSYS"]
    fn guard_child() {
        let effect = std::env::var("LIGHTHOUSE_GUARD_TEST_EFFECT").unwrap();
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: the limit is initialized and lives through this synchronous call.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) }, 0);
        super::install().unwrap();
        match effect.as_str() {
            "socket" => {
                let _listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            }
            "wait" => {
                let mutex = parking_lot::Mutex::new(());
                let _held = mutex.lock();
                let _blocked = mutex.lock();
            }
            "thread" => {
                std::thread::spawn(|| ()).join().unwrap();
            }
            "entropy" => {
                let mut bytes = [0u8; 8];
                // SAFETY: the output buffer is valid for the requested length.
                // Raw syscalls deliberately bypass MadSim's libc interception.
                unsafe { libc::syscall(libc::SYS_getrandom, bytes.as_mut_ptr(), bytes.len(), 0) };
            }
            "clock" => {
                let mut time = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                // SAFETY: the output pointer refers to a valid timespec.
                unsafe { libc::syscall(libc::SYS_clock_gettime, libc::CLOCK_MONOTONIC, &mut time) };
            }
            _ => panic!("unknown guard probe: {effect}"),
        }
        panic!("native {effect} escaped the simulation guard");
    }
}
