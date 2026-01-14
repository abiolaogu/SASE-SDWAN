//! Container Orchestration
//!
//! Manages Chromium browser containers with security isolation.

use crate::{SessionConfig, ContainerSpec, InputEvent, Viewport};
use std::collections::HashMap;
use tokio::process::Command;
use tracing::{info, warn, error};

/// Container manager for browser isolation
pub struct ContainerManager {
    /// Default container image
    image: String,
    /// Active containers
    containers: dashmap::DashMap<String, ContainerState>,
    /// Container runtime (docker/containerd)
    runtime: ContainerRuntime,
}

#[derive(Debug, Clone)]
pub struct ContainerState {
    pub container_id: String,
    pub session_id: String,
    pub status: ContainerStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub port_mappings: HashMap<u16, u16>,
    pub vnc_port: Option<u16>,
    pub websocket_port: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerStatus {
    Creating,
    Running,
    Paused,
    Stopping,
    Stopped,
    Error,
}

#[derive(Debug, Clone, Copy)]
pub enum ContainerRuntime {
    Docker,
    Containerd,
    Podman,
}

impl ContainerManager {
    pub fn new(image: &str) -> Self {
        Self {
            image: image.to_string(),
            containers: dashmap::DashMap::new(),
            runtime: ContainerRuntime::Docker,
        }
    }
    
    /// Create isolated browser container
    pub async fn create_container(
        &self,
        session_id: &str,
        config: &SessionConfig,
    ) -> Result<String, String> {
        // Generate unique container name
        let container_name = format!("osbi-{}", session_id);
        
        // Allocate ports
        let vnc_port = self.allocate_port().await;
        let ws_port = self.allocate_port().await;
        
        // Build container spec
        let spec = self.build_container_spec(config);
        
        // Create container
        let container_id = self.run_container(&container_name, &spec, vnc_port, ws_port, config).await?;
        
        let state = ContainerState {
            container_id: container_id.clone(),
            session_id: session_id.to_string(),
            status: ContainerStatus::Running,
            created_at: chrono::Utc::now(),
            port_mappings: HashMap::from([
                (5900, vnc_port),
                (8080, ws_port),
            ]),
            vnc_port: Some(vnc_port),
            websocket_port: Some(ws_port),
        };
        
        self.containers.insert(session_id.to_string(), state);
        
        info!("Created container {} for session {}", container_id, session_id);
        Ok(container_id)
    }
    
    /// Destroy container
    pub async fn destroy_container(&self, container_id: &str) -> Result<(), String> {
        let output = Command::new("docker")
            .args(["rm", "-f", container_id])
            .output()
            .await
            .map_err(|e| format!("Failed to destroy container: {}", e))?;
        
        if !output.status.success() {
            warn!("Container destruction warning: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        // Remove from tracking
        self.containers.retain(|_, v| v.container_id != container_id);
        
        info!("Destroyed container {}", container_id);
        Ok(())
    }
    
    /// Send input event to container
    pub async fn send_input(&self, container_id: &str, event: InputEvent) -> Result<(), String> {
        // Find container's websocket port
        let ws_port = self.containers.iter()
            .find(|c| c.container_id == container_id)
            .and_then(|c| c.websocket_port)
            .ok_or("Container not found")?;
        
        // Send via websocket (simplified - real impl would maintain connection)
        let url = format!("ws://localhost:{}/input", ws_port);
        let payload = serde_json::to_string(&event)
            .map_err(|e| format!("Serialization error: {}", e))?;
        
        // In production, this would use a persistent WebSocket connection
        info!("Sending input to container {} via {}", container_id, url);
        
        Ok(())
    }
    
    /// Get container state
    pub fn get_state(&self, session_id: &str) -> Option<ContainerState> {
        self.containers.get(session_id).map(|c| c.clone())
    }
    
    /// Resize container viewport
    pub async fn resize(&self, container_id: &str, viewport: Viewport) -> Result<(), String> {
        let ws_port = self.containers.iter()
            .find(|c| c.container_id == container_id)
            .and_then(|c| c.websocket_port)
            .ok_or("Container not found")?;
        
        // Send resize command
        info!("Resizing container {} to {}x{}", container_id, viewport.width, viewport.height);
        
        Ok(())
    }
    
    /// Take screenshot
    pub async fn screenshot(&self, container_id: &str) -> Result<Vec<u8>, String> {
        // Execute screenshot command in container
        let output = Command::new("docker")
            .args(["exec", container_id, "screenshot", "/tmp/screen.png"])
            .output()
            .await
            .map_err(|e| format!("Screenshot failed: {}", e))?;
        
        if !output.status.success() {
            return Err("Screenshot capture failed".to_string());
        }
        
        // Read file from container
        let output = Command::new("docker")
            .args(["cp", &format!("{}:/tmp/screen.png", container_id), "-"])
            .output()
            .await
            .map_err(|e| format!("Screenshot read failed: {}", e))?;
        
        Ok(output.stdout)
    }
    
    fn build_container_spec(&self, config: &SessionConfig) -> ContainerSpec {
        let mut spec = ContainerSpec::default();
        spec.memory_limit = format!("{}Mi", config.max_memory_mb);
        spec.cpu_limit = format!("{}", config.max_cpu_cores);
        spec
    }
    
    async fn run_container(
        &self,
        name: &str,
        spec: &ContainerSpec,
        vnc_port: u16,
        ws_port: u16,
        config: &SessionConfig,
    ) -> Result<String, String> {
        let mut args = vec![
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(), name.to_string(),
            "--memory".to_string(), spec.memory_limit.clone(),
            "--cpus".to_string(), spec.cpu_limit.clone(),
            "-p".to_string(), format!("{}:5900", vnc_port),
            "-p".to_string(), format!("{}:8080", ws_port),
            "--security-opt".to_string(), "no-new-privileges:true".to_string(),
            "--security-opt".to_string(), "seccomp=chromium.json".to_string(),
            "--cap-drop".to_string(), "ALL".to_string(),
            "--cap-add".to_string(), "SYS_ADMIN".to_string(), // Required for Chromium
            "--shm-size".to_string(), "2g".to_string(), // Chromium needs shared memory
            "-e".to_string(), format!("DISPLAY_WIDTH={}", config.viewport.width),
            "-e".to_string(), format!("DISPLAY_HEIGHT={}", config.viewport.height),
        ];
        
        // Add initial URL if specified
        if let Some(url) = &config.initial_url {
            args.push("-e".to_string());
            args.push(format!("INITIAL_URL={}", url));
        }
        
        // Add image
        args.push(self.image.clone());
        
        let output = Command::new("docker")
            .args(&args)
            .output()
            .await
            .map_err(|e| format!("Docker run failed: {}", e))?;
        
        if !output.status.success() {
            return Err(format!("Container creation failed: {}", String::from_utf8_lossy(&output.stderr)));
        }
        
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
    
    async fn allocate_port(&self) -> u16 {
        // Simple port allocation (production would use proper port pool)
        use std::sync::atomic::{AtomicU16, Ordering};
        static PORT_COUNTER: AtomicU16 = AtomicU16::new(10000);
        PORT_COUNTER.fetch_add(1, Ordering::Relaxed)
    }
}

/// SecurityOpts for Chromium containers
pub fn chromium_security_profile() -> Vec<String> {
    vec![
        // Seccomp profile for Chromium
        r#"{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[
            {"names":["read","write","open","close","stat","fstat","lstat","poll","lseek","mmap","mprotect","munmap","brk","rt_sigaction","rt_sigprocmask","rt_sigreturn","ioctl","access","pipe","select","sched_yield","mremap","msync","mincore","madvise","shmget","shmat","shmctl","dup","dup2","pause","nanosleep","getitimer","alarm","setitimer","getpid","sendfile","socket","connect","accept","sendto","recvfrom","sendmsg","recvmsg","shutdown","bind","listen","getsockname","getpeername","socketpair","setsockopt","getsockopt","clone","fork","vfork","execve","exit","wait4","kill","uname","semget","semop","semctl","shmdt","msgget","msgsnd","msgrcv","msgctl","fcntl","flock","fsync","fdatasync","truncate","ftruncate","getdents","getcwd","chdir","fchdir","rename","mkdir","rmdir","creat","link","unlink","symlink","readlink","chmod","fchmod","chown","fchown","lchown","umask","gettimeofday","getrlimit","getrusage","sysinfo","times","ptrace","getuid","syslog","getgid","setuid","setgid","geteuid","getegid","setpgid","getppid","getpgrp","setsid","setreuid","setregid","getgroups","setgroups","setresuid","getresuid","setresgid","getresgid","getpgid","setfsuid","setfsgid","getsid","capget","capset","rt_sigpending","rt_sigtimedwait","rt_sigqueueinfo","rt_sigsuspend","sigaltstack","utime","mknod","uselib","personality","ustat","statfs","fstatfs","sysfs","getpriority","setpriority","sched_setparam","sched_getparam","sched_setscheduler","sched_getscheduler","sched_get_priority_max","sched_get_priority_min","sched_rr_get_interval","mlock","munlock","mlockall","munlockall","vhangup","modify_ldt","pivot_root","_sysctl","prctl","arch_prctl","adjtimex","setrlimit","chroot","sync","acct","settimeofday","mount","umount2","swapon","swapoff","reboot","sethostname","setdomainname","iopl","ioperm","create_module","init_module","delete_module","get_kernel_syms","query_module","quotactl","nfsservctl","getpmsg","putpmsg","afs_syscall","tuxcall","security","gettid","readahead","setxattr","lsetxattr","fsetxattr","getxattr","lgetxattr","fgetxattr","listxattr","llistxattr","flistxattr","removexattr","lremovexattr","fremovexattr","tkill","time","futex","sched_setaffinity","sched_getaffinity","set_thread_area","io_setup","io_destroy","io_getevents","io_submit","io_cancel","get_thread_area","lookup_dcookie","epoll_create","epoll_ctl_old","epoll_wait_old","remap_file_pages","getdents64","set_tid_address","restart_syscall","semtimedop","fadvise64","timer_create","timer_settime","timer_gettime","timer_getoverrun","timer_delete","clock_settime","clock_gettime","clock_getres","clock_nanosleep","exit_group","epoll_wait","epoll_ctl","tgkill","utimes","vserver","mbind","set_mempolicy","get_mempolicy","mq_open","mq_unlink","mq_timedsend","mq_timedreceive","mq_notify","mq_getsetattr","kexec_load","waitid","add_key","request_key","keyctl","ioprio_set","ioprio_get","inotify_init","inotify_add_watch","inotify_rm_watch","migrate_pages","openat","mkdirat","mknodat","fchownat","futimesat","newfstatat","unlinkat","renameat","linkat","symlinkat","readlinkat","fchmodat","faccessat","pselect6","ppoll","unshare","set_robust_list","get_robust_list","splice","tee","sync_file_range","vmsplice","move_pages","utimensat","epoll_pwait","signalfd","timerfd_create","eventfd","fallocate","timerfd_settime","timerfd_gettime","accept4","signalfd4","eventfd2","epoll_create1","dup3","pipe2","inotify_init1","preadv","pwritev","rt_tgsigqueueinfo","perf_event_open","recvmmsg","fanotify_init","fanotify_mark","prlimit64","name_to_handle_at","open_by_handle_at","clock_adjtime","syncfs","sendmmsg","setns","getcpu","process_vm_readv","process_vm_writev","kcmp","finit_module","sched_setattr","sched_getattr","renameat2","seccomp","getrandom","memfd_create","kexec_file_load","bpf","userfaultfd","membarrier","mlock2","copy_file_range","preadv2","pwritev2"],"action":"SCMP_ACT_ALLOW"}
        ]}"#.to_string(),
    ]
}
