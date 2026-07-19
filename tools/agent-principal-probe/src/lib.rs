use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const MAX_PATH_LEN: usize = 4096;
const MAX_RESOURCE_ARGS: usize = 64;
const MAX_ENV_NAME_LEN: usize = 256;
const MAX_SUPP_GIDS: usize = 128;

#[derive(Debug, Serialize)]
pub struct ProbeReport {
    pub pid: u32,
    pub ppid: u32,
    pub start_time: String,
    pub uid: u32,
    pub gid: u32,
    pub supplementary_gids: Vec<u32>,
    pub namespaces: BTreeMap<String, u64>,
    pub cgroup_v2_path: String,
    pub no_new_privs: bool,
    pub cap_env_names: Vec<String>,
    pub fd3: Fd3Info,
    pub resources: Vec<ResourceOutcome>,
}

#[derive(Debug, Serialize)]
pub struct Fd3Info {
    pub present: bool,
    pub fd_type: String,
    pub peer_uid: Option<u32>,
    pub peer_gid: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ResourceOutcome {
    pub path: String,
    pub outcome: String,
    pub errno: Option<String>,
}

pub fn collect_process_info() -> (u32, u32, String) {
    let pid = unsafe { libc::getpid() } as u32;
    let ppid = unsafe { libc::getppid() } as u32;
    let start_time = read_start_time(pid).unwrap_or_else(|_| "unavailable".to_string());
    (pid, ppid, start_time)
}

fn read_start_time(pid: u32) -> io::Result<String> {
    let stat_path = format!("/proc/{}/stat", pid);
    let content = fs::read_to_string(&stat_path)?;
    let after_comm = content
        .rfind(')')
        .map(|i| &content[i + 2..])
        .ok_or_else(|| io::Error::other("bad /proc/pid/stat"))?;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    if fields.len() < 20 {
        return Err(io::Error::other("insufficient stat fields"));
    }
    Ok(fields[19].to_string())
}

pub fn collect_identity() -> (u32, u32, Vec<u32>) {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let mut groups = [0u32; MAX_SUPP_GIDS];
    let ngroups = unsafe { libc::getgroups(MAX_SUPP_GIDS as i32, groups.as_mut_ptr()) };
    let supplementary_gids = if ngroups > 0 {
        groups[..ngroups as usize].to_vec()
    } else {
        Vec::new()
    };
    (uid, gid, supplementary_gids)
}

pub fn collect_namespace_inodes() -> BTreeMap<String, u64> {
    let ns_names = [
        "cgroup",
        "ipc",
        "mnt",
        "net",
        "pid",
        "pid_for_children",
        "time",
        "time_for_children",
        "user",
        "uts",
    ];
    let mut map = BTreeMap::new();
    for name in &ns_names {
        let link_path = format!("/proc/self/ns/{}", name);
        if let Ok(meta) = fs::metadata(&link_path) {
            map.insert(name.to_string(), meta.ino());
        }
    }
    map
}

pub fn collect_cgroup_v2_path() -> String {
    match fs::read_to_string("/proc/self/cgroup") {
        Ok(content) => {
            for line in content.lines() {
                if let Some(stripped) = line.strip_prefix("0::") {
                    return stripped.to_string();
                }
            }
            if let Some(first) = content.lines().next() {
                let parts: Vec<&str> = first.splitn(3, ':').collect();
                if parts.len() == 3 {
                    return parts[2].to_string();
                }
            }
            "unavailable".to_string()
        }
        Err(_) => "unavailable".to_string(),
    }
}

pub fn collect_no_new_privs() -> bool {
    match fs::read_to_string("/proc/self/status") {
        Ok(content) => {
            for line in content.lines() {
                if line.starts_with("NoNewPrivs:")
                    && let Some(val) = line.split_whitespace().nth(1)
                {
                    return val == "1";
                }
            }
            false
        }
        Err(_) => false,
    }
}

pub fn collect_cap_env_names() -> Vec<String> {
    let mut names = Vec::new();
    for (key, _) in std::env::vars_os() {
        let key_str = key.to_string_lossy();
        if key_str.len() > MAX_ENV_NAME_LEN {
            continue;
        }
        let upper = key_str.to_uppercase();
        if upper.contains("CAP_")
            || upper.starts_with("PASSLESS_CAP_")
            || upper.starts_with("PASSLESS_PRIVILEGED_")
            || upper.starts_with("LD_PRELOAD")
            || upper.starts_with("LD_LIBRARY_PATH")
        {
            names.push(key_str.into_owned());
        }
    }
    names.sort();
    names
}

pub fn collect_fd3_info() -> Fd3Info {
    let fd_path = "/proc/self/fd/3";
    let target = match fs::read_link(fd_path) {
        Ok(t) => t,
        Err(_) => {
            return Fd3Info {
                present: false,
                fd_type: "absent".to_string(),
                peer_uid: None,
                peer_gid: None,
            };
        }
    };
    let target_str = target.to_string_lossy().into_owned();
    let fd_type = if target_str.starts_with("socket:") {
        "socket".to_string()
    } else if target_str.starts_with("pipe:") {
        "pipe".to_string()
    } else if target_str.starts_with("anon_inode:") {
        "anon_inode".to_string()
    } else if Path::new(&target).exists() {
        "file".to_string()
    } else {
        "other".to_string()
    };

    let (peer_uid, peer_gid) = if fd_type == "socket" {
        get_socket_peer_creds(3)
    } else {
        (None, None)
    };

    Fd3Info {
        present: true,
        fd_type,
        peer_uid,
        peer_gid,
    }
}

fn get_socket_peer_creds(fd: i32) -> (Option<u32>, Option<u32>) {
    unsafe {
        let mut ucred: libc::ucred = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::ucred>() as u32;
        let ret = libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if ret == 0 {
            (Some(ucred.uid), Some(ucred.gid))
        } else {
            (None, None)
        }
    }
}

pub fn validate_resource_path(p: &str) -> Result<PathBuf, String> {
    if p.len() > MAX_PATH_LEN {
        return Err(format!("path exceeds {} bytes", MAX_PATH_LEN));
    }
    if !p.starts_with('/') {
        return Err("path must be absolute".to_string());
    }

    let mut accumulated = String::new();
    for component in p.split('/').filter(|c| !c.is_empty()) {
        accumulated.push('/');
        accumulated.push_str(component);
        let component_path = Path::new(&accumulated);
        if let Ok(meta) = fs::symlink_metadata(component_path)
            && meta.file_type().is_symlink()
        {
            return Err(format!("symlink in path: {}", accumulated));
        }
    }

    let path = PathBuf::from(p);
    if let Ok(meta) = fs::symlink_metadata(&path)
        && meta.file_type().is_symlink()
    {
        return Err(format!("path is a symlink: {}", p));
    }
    Ok(path)
}

pub fn probe_resource(path: &Path) -> ResourceOutcome {
    let path_str = path.to_string_lossy().into_owned();
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes());
    let c_path = match c_path {
        Ok(c) => c,
        Err(e) => {
            return ResourceOutcome {
                path: path_str,
                outcome: "error".to_string(),
                errno: Some(format!("invalid path: {}", e)),
            };
        }
    };

    let meta = fs::symlink_metadata(path);
    let is_socket = meta
        .as_ref()
        .map(|m| m.file_type().is_socket())
        .unwrap_or(false);

    if is_socket {
        probe_socket(path, &path_str, &c_path)
    } else {
        probe_file(path, &path_str, &c_path)
    }
}

fn probe_file(_path: &Path, path_str: &str, c_path: &std::ffi::CString) -> ResourceOutcome {
    let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC;
    let fd = unsafe { libc::open(c_path.as_ptr(), flags) };
    if fd >= 0 {
        unsafe { libc::close(fd) };
        ResourceOutcome {
            path: path_str.to_string(),
            outcome: "open_ok".to_string(),
            errno: None,
        }
    } else {
        let errno = io::Error::last_os_error();
        ResourceOutcome {
            path: path_str.to_string(),
            outcome: "open_denied".to_string(),
            errno: Some(errno_kind_str(errno)),
        }
    }
}

fn probe_socket(_path: &Path, path_str: &str, c_path: &std::ffi::CString) -> ResourceOutcome {
    unsafe {
        let fd = libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        );
        if fd < 0 {
            return ResourceOutcome {
                path: path_str.to_string(),
                outcome: "error".to_string(),
                errno: Some("socket_create_failed".to_string()),
            };
        }

        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as _;
        let sun_path = &mut addr.sun_path[..];
        let path_bytes = c_path.as_bytes_with_nul();
        if path_bytes.len() > sun_path.len() + 1 {
            libc::close(fd);
            return ResourceOutcome {
                path: path_str.to_string(),
                outcome: "error".to_string(),
                errno: Some("path_too_long_for_sockaddr".to_string()),
            };
        }
        for (i, &b) in path_bytes.iter().enumerate() {
            if i >= sun_path.len() {
                break;
            }
            sun_path[i] = b as libc::c_char;
        }

        let ret = libc::connect(
            fd,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as u32,
        );

        if ret == 0 {
            libc::close(fd);
            return ResourceOutcome {
                path: path_str.to_string(),
                outcome: "connect_ok".to_string(),
                errno: None,
            };
        }

        let errno = io::Error::last_os_error();
        let raw_errno = errno.raw_os_error().unwrap_or(0);

        if raw_errno == libc::EINPROGRESS || raw_errno == libc::EAGAIN {
            let mut so_error: i32 = 0;
            let mut len = std::mem::size_of::<i32>() as u32;
            let get_ret = libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut so_error as *mut i32 as *mut libc::c_void,
                &mut len,
            );
            libc::close(fd);

            if get_ret == 0 && so_error == 0 {
                ResourceOutcome {
                    path: path_str.to_string(),
                    outcome: "connect_ok".to_string(),
                    errno: None,
                }
            } else {
                let err_str = if get_ret == 0 {
                    errno_kind_str(io::Error::from_raw_os_error(so_error))
                } else {
                    errno_kind_str(errno)
                };
                ResourceOutcome {
                    path: path_str.to_string(),
                    outcome: "connect_denied".to_string(),
                    errno: Some(err_str),
                }
            }
        } else {
            libc::close(fd);
            ResourceOutcome {
                path: path_str.to_string(),
                outcome: "connect_denied".to_string(),
                errno: Some(errno_kind_str(errno)),
            }
        }
    }
}

fn errno_kind_str(e: io::Error) -> String {
    match e.kind() {
        io::ErrorKind::PermissionDenied => "EACCES".to_string(),
        io::ErrorKind::NotFound => "ENOENT".to_string(),
        io::ErrorKind::ConnectionRefused => "ECONNREFUSED".to_string(),
        _ => {
            let raw = e.raw_os_error().unwrap_or(0);
            match raw {
                libc::EACCES => "EACCES".to_string(),
                libc::ENOENT => "ENOENT".to_string(),
                libc::ECONNREFUSED => "ECONNREFUSED".to_string(),
                libc::ECONNRESET => "ECONNRESET".to_string(),
                libc::EINPROGRESS => "EINPROGRESS".to_string(),
                libc::EAGAIN => "EAGAIN".to_string(),
                libc::ENOTDIR => "ENOTDIR".to_string(),
                libc::ELOOP => "ELOOP".to_string(),
                _ => format!("errno_{}", raw),
            }
        }
    }
}

pub fn build_report(resource_paths: &[String]) -> Result<ProbeReport, String> {
    if resource_paths.len() > MAX_RESOURCE_ARGS {
        return Err(format!(
            "too many resource args (max {})",
            MAX_RESOURCE_ARGS
        ));
    }

    let (pid, ppid, start_time) = collect_process_info();
    let (uid, gid, supplementary_gids) = collect_identity();
    let namespaces = collect_namespace_inodes();
    let cgroup_v2_path = collect_cgroup_v2_path();
    let no_new_privs = collect_no_new_privs();
    let cap_env_names = collect_cap_env_names();
    let fd3 = collect_fd3_info();

    let mut resources = Vec::new();
    for p in resource_paths {
        match validate_resource_path(p) {
            Ok(validated) => {
                resources.push(probe_resource(&validated));
            }
            Err(e) => {
                resources.push(ResourceOutcome {
                    path: p.clone(),
                    outcome: "rejected".to_string(),
                    errno: Some(e),
                });
            }
        }
    }

    Ok(ProbeReport {
        pid,
        ppid,
        start_time,
        uid,
        gid,
        supplementary_gids,
        namespaces,
        cgroup_v2_path,
        no_new_privs,
        cap_env_names,
        fd3,
        resources,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_collect_process_info_returns_nonzero_pid() {
        let (pid, ppid, _start_time) = collect_process_info();
        assert!(pid > 0);
        assert!(ppid > 0);
    }

    #[test]
    fn test_collect_identity_returns_current_user() {
        let (uid, gid, _supp) = collect_identity();
        let expected_uid = unsafe { libc::getuid() };
        let expected_gid = unsafe { libc::getgid() };
        assert_eq!(uid, expected_uid);
        assert_eq!(gid, expected_gid);
    }

    #[test]
    fn test_collect_identity_supplementary_gids_bounded() {
        let (_, _, supp) = collect_identity();
        assert!(supp.len() <= MAX_SUPP_GIDS);
    }

    #[test]
    fn test_collect_namespace_inodes_has_pid() {
        let ns = collect_namespace_inodes();
        assert!(ns.contains_key("pid"));
        assert!(ns["pid"] > 0);
    }

    #[test]
    fn test_collect_namespace_inodes_has_expected_keys() {
        let ns = collect_namespace_inodes();
        assert!(ns.contains_key("mnt"));
        assert!(ns.contains_key("net"));
        assert!(ns.contains_key("user"));
    }

    #[test]
    fn test_collect_namespace_inodes_uses_metadata() {
        let ns = collect_namespace_inodes();
        let pid_ino = ns.get("pid").unwrap();
        let expected_path = "/proc/self/ns/pid";
        let meta = fs::metadata(expected_path).unwrap();
        assert_eq!(*pid_ino, meta.ino());
    }

    #[test]
    fn test_collect_cgroup_v2_path_not_empty() {
        let path = collect_cgroup_v2_path();
        assert!(!path.is_empty());
    }

    #[test]
    fn test_collect_no_new_privs_returns_bool() {
        let _nnp = collect_no_new_privs();
    }

    #[test]
    fn test_collect_cap_env_names_clean_env() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let names = collect_cap_env_names();
        for name in &names {
            assert!(name.len() <= MAX_ENV_NAME_LEN);
        }
    }

    #[test]
    fn test_collect_cap_env_names_detects_cap_vars() {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("PASSLESS_CAP_TEST_PROBE", "1") };
        let names = collect_cap_env_names();
        assert!(names.iter().any(|n| n == "PASSLESS_CAP_TEST_PROBE"));
        unsafe { std::env::remove_var("PASSLESS_CAP_TEST_PROBE") };
    }

    #[test]
    fn test_collect_cap_env_names_detects_privileged_vars() {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("PASSLESS_PRIVILEGED_TEST_PROBE", "1") };
        let names = collect_cap_env_names();
        assert!(names.iter().any(|n| n == "PASSLESS_PRIVILEGED_TEST_PROBE"));
        unsafe { std::env::remove_var("PASSLESS_PRIVILEGED_TEST_PROBE") };
    }

    #[test]
    fn test_collect_cap_env_names_never_includes_values() {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("PASSLESS_CAP_SENSITIVE", "secret_value_12345") };
        let names = collect_cap_env_names();
        for name in &names {
            assert!(!name.contains("secret_value_12345"));
        }
        unsafe { std::env::remove_var("PASSLESS_CAP_SENSITIVE") };
    }

    #[test]
    fn test_collect_fd3_absent() {
        let info = collect_fd3_info();
        assert!(!info.present);
        assert_eq!(info.fd_type, "absent");
        assert!(info.peer_uid.is_none());
        assert!(info.peer_gid.is_none());
    }

    #[test]
    fn test_validate_resource_path_rejects_relative() {
        let result = validate_resource_path("relative/path");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("absolute"));
    }

    #[test]
    fn test_validate_resource_path_rejects_too_long() {
        let long_path = format!("/{}", "a".repeat(MAX_PATH_LEN + 1));
        let result = validate_resource_path(&long_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds"));
    }

    #[test]
    fn test_validate_resource_path_rejects_symlink() {
        let dir = std::env::temp_dir().join("probe_test_symlink");
        let target = dir.join("target");
        let link = dir.join("link");
        let _ = fs::remove_file(&target);
        let _ = fs::remove_file(&link);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(&target, b"test").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = validate_resource_path(link.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("symlink"));

        let _ = fs::remove_file(&target);
        let _ = fs::remove_file(&link);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_validate_resource_path_rejects_symlink_in_middle() {
        let dir = std::env::temp_dir().join("probe_test_symlink_mid");
        let real_subdir = dir.join("real");
        let link_dir = dir.join("link");
        let file_in_link = link_dir.join("file");
        let _ = fs::remove_file(&file_in_link);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&real_subdir).unwrap();
        fs::write(real_subdir.join("file"), b"test").unwrap();
        std::os::unix::fs::symlink(&real_subdir, &link_dir).unwrap();

        let result = validate_resource_path(file_in_link.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("symlink"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_validate_resource_path_accepts_regular_file() {
        let dir = std::env::temp_dir().join("probe_test_regular");
        let file = dir.join("regular_file");
        let _ = fs::remove_file(&file);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(&file, b"test").unwrap();

        let result = validate_resource_path(file.to_str().unwrap());
        assert!(result.is_ok());

        let _ = fs::remove_file(&file);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_validate_resource_path_accepts_nonexistent() {
        let result = validate_resource_path("/nonexistent/path/that/does/not/exist");
        assert!(result.is_ok());
    }

    #[test]
    fn test_probe_resource_readable_file() {
        let dir = std::env::temp_dir().join("probe_test_readable");
        let file = dir.join("readable");
        let _ = fs::remove_file(&file);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(&file, b"test content").unwrap();

        let outcome = probe_resource(&file);
        assert_eq!(outcome.outcome, "open_ok");
        assert!(outcome.errno.is_none());

        let _ = fs::remove_file(&file);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_probe_resource_permission_denied() {
        let dir = std::env::temp_dir().join("probe_test_denied");
        let file = dir.join("noperm");
        let _ = fs::remove_file(&file);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(&file, b"secret").unwrap();
        let mut perms = fs::metadata(&file).unwrap().permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&file, perms).unwrap();

        let outcome = probe_resource(&file);
        let uid = unsafe { libc::getuid() };
        if uid == 0 {
            assert_eq!(outcome.outcome, "open_ok");
        } else {
            assert_eq!(outcome.outcome, "open_denied");
            assert!(outcome.errno.is_some());
        }

        let mut perms = fs::metadata(&file).unwrap().permissions();
        perms.set_mode(0o644);
        let _ = fs::set_permissions(&file, perms);
        let _ = fs::remove_file(&file);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_probe_resource_nonexistent() {
        let outcome = probe_resource(Path::new("/nonexistent/probe/test/path"));
        assert_eq!(outcome.outcome, "open_denied");
        assert_eq!(outcome.errno.as_deref(), Some("ENOENT"));
    }

    #[test]
    fn test_probe_resource_unix_socket() {
        let dir = std::env::temp_dir().join("probe_test_sock");
        let sock_path = dir.join("test.sock");
        let _ = fs::remove_file(&sock_path);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let c_path = std::ffi::CString::new(sock_path.to_str().unwrap().as_bytes()).unwrap();
        unsafe {
            let listen_fd = libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0);
            assert!(listen_fd >= 0);
            let mut addr: libc::sockaddr_un = std::mem::zeroed();
            addr.sun_family = libc::AF_UNIX as _;
            let path_bytes = c_path.as_bytes_with_nul();
            for (i, &b) in path_bytes.iter().enumerate() {
                if i >= addr.sun_path.len() {
                    break;
                }
                addr.sun_path[i] = b as libc::c_char;
            }
            let bind_ret = libc::bind(
                listen_fd,
                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_un>() as u32,
            );
            if bind_ret == 0 {
                libc::listen(listen_fd, 1);

                let outcome = probe_resource(&sock_path);
                assert_eq!(outcome.outcome, "connect_ok");

                libc::close(listen_fd);
            }
        }

        let _ = fs::remove_file(&sock_path);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_report_rejects_too_many_args() {
        let paths: Vec<String> = (0..MAX_RESOURCE_ARGS + 1)
            .map(|i| format!("/tmp/probe_test_{}", i))
            .collect();
        let result = build_report(&paths);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too many"));
    }

    #[test]
    fn test_build_report_with_empty_args() {
        let report = build_report(&[]).unwrap();
        assert!(report.pid > 0);
        assert!(report.resources.is_empty());
        assert!(report.namespaces.contains_key("pid"));
    }

    #[test]
    fn test_build_report_with_valid_resource() {
        let dir = std::env::temp_dir().join("probe_test_build");
        let file = dir.join("build_test");
        let _ = fs::remove_file(&file);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(&file, b"test").unwrap();

        let report = build_report(&[file.to_string_lossy().into_owned()]).unwrap();
        assert_eq!(report.resources.len(), 1);
        assert_eq!(report.resources[0].outcome, "open_ok");

        let _ = fs::remove_file(&file);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_report_with_symlink_rejected() {
        let dir = std::env::temp_dir().join("probe_test_build_sym");
        let target = dir.join("target");
        let link = dir.join("link");
        let _ = fs::remove_file(&target);
        let _ = fs::remove_file(&link);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(&target, b"test").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let report = build_report(&[link.to_string_lossy().into_owned()]).unwrap();
        assert_eq!(report.resources.len(), 1);
        assert_eq!(report.resources[0].outcome, "rejected");

        let _ = fs::remove_file(&target);
        let _ = fs::remove_file(&link);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_report_serialization_no_secrets() {
        let report = build_report(&[]).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.get("pid").is_some());
        assert!(parsed.get("ppid").is_some());
        assert!(parsed.get("uid").is_some());
        assert!(parsed.get("gid").is_some());
        assert!(parsed.get("namespaces").is_some());
        assert!(parsed.get("cgroup_v2_path").is_some());
        assert!(parsed.get("no_new_privs").is_some());
        assert!(parsed.get("cap_env_names").is_some());
        assert!(parsed.get("fd3").is_some());
        assert!(parsed.get("resources").is_some());
        assert!(parsed.get("supplementary_gids").is_some());
        assert!(parsed.get("start_time").is_some());

        assert!(parsed.get("private_key").is_none());
        assert!(parsed.get("secret").is_none());
        assert!(parsed.get("password").is_none());
        assert!(parsed.get("token").is_none());
    }

    #[test]
    fn test_report_field_types() {
        let report = build_report(&[]).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed["pid"].is_number());
        assert!(parsed["ppid"].is_number());
        assert!(parsed["start_time"].is_string());
        assert!(parsed["uid"].is_number());
        assert!(parsed["gid"].is_number());
        assert!(parsed["supplementary_gids"].is_array());
        assert!(parsed["namespaces"].is_object());
        assert!(parsed["cgroup_v2_path"].is_string());
        assert!(parsed["no_new_privs"].is_boolean());
        assert!(parsed["cap_env_names"].is_array());
        assert!(parsed["fd3"].is_object());
        assert!(parsed["resources"].is_array());
    }

    #[test]
    fn test_fd3_info_field_types() {
        let info = collect_fd3_info();
        let json = serde_json::to_string(&info).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed["present"].is_boolean());
        assert!(parsed["fd_type"].is_string());
    }

    #[test]
    fn test_resource_outcome_field_types() {
        let outcome = probe_resource(Path::new("/nonexistent/test"));
        let json = serde_json::to_string(&outcome).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed["path"].is_string());
        assert!(parsed["outcome"].is_string());
    }

    #[test]
    fn test_errno_kind_str_mapping() {
        let e = io::Error::from_raw_os_error(libc::EACCES);
        assert_eq!(errno_kind_str(e), "EACCES");

        let e = io::Error::from_raw_os_error(libc::ENOENT);
        assert_eq!(errno_kind_str(e), "ENOENT");

        let e = io::Error::from_raw_os_error(libc::ECONNREFUSED);
        assert_eq!(errno_kind_str(e), "ECONNREFUSED");
    }

    #[test]
    fn test_cap_env_names_sorted() {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("PASSLESS_CAP_ZZZ", "1") };
        unsafe { std::env::set_var("PASSLESS_CAP_AAA", "1") };
        let names = collect_cap_env_names();
        let cap_names: Vec<&String> = names
            .iter()
            .filter(|n| n.starts_with("PASSLESS_CAP_"))
            .collect();
        if cap_names.len() >= 2 {
            let aaa_idx = cap_names
                .iter()
                .position(|n| n.as_str() == "PASSLESS_CAP_AAA");
            let zzz_idx = cap_names
                .iter()
                .position(|n| n.as_str() == "PASSLESS_CAP_ZZZ");
            if let (Some(a), Some(z)) = (aaa_idx, zzz_idx) {
                assert!(a < z);
            }
        }
        unsafe { std::env::remove_var("PASSLESS_CAP_ZZZ") };
        unsafe { std::env::remove_var("PASSLESS_CAP_AAA") };
    }

    #[test]
    fn test_validate_resource_path_max_boundary() {
        let exact_path = format!("/{}", "a".repeat(MAX_PATH_LEN - 1));
        assert!(validate_resource_path(&exact_path).is_ok());

        let over_path = format!("/{}", "a".repeat(MAX_PATH_LEN));
        assert!(validate_resource_path(&over_path).is_err());
    }

    #[test]
    fn test_probe_socket_nonexistent() {
        let dir = std::env::temp_dir().join("probe_test_nosock");
        let sock_path = dir.join("nosock.sock");
        let _ = fs::remove_file(&sock_path);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let c_path = std::ffi::CString::new(sock_path.to_str().unwrap().as_bytes()).unwrap();
        unsafe {
            let fd = libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0);
            assert!(fd >= 0);
            let mut addr: libc::sockaddr_un = std::mem::zeroed();
            addr.sun_family = libc::AF_UNIX as _;
            let path_bytes = c_path.as_bytes_with_nul();
            for (i, &b) in path_bytes.iter().enumerate() {
                if i >= addr.sun_path.len() {
                    break;
                }
                addr.sun_path[i] = b as libc::c_char;
            }
            let bind_ret = libc::bind(
                fd,
                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_un>() as u32,
            );
            assert_eq!(bind_ret, 0);
            libc::close(fd);
        }

        let outcome = probe_resource(&sock_path);
        assert_eq!(outcome.outcome, "connect_denied");

        let _ = fs::remove_file(&sock_path);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_build_report_mixed_resources() {
        let dir = std::env::temp_dir().join("probe_test_mixed");
        let file = dir.join("file");
        let _ = fs::remove_file(&file);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(&file, b"test").unwrap();

        let paths = vec![
            file.to_string_lossy().into_owned(),
            "/nonexistent/probe/path".to_string(),
        ];
        let report = build_report(&paths).unwrap();
        assert_eq!(report.resources.len(), 2);
        assert_eq!(report.resources[0].outcome, "open_ok");
        assert_eq!(report.resources[1].outcome, "open_denied");

        let _ = fs::remove_file(&file);
        let _ = fs::remove_dir_all(&dir);
    }
}
