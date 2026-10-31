use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    process::{Command, Output},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub struct Server {
    pub url: String,
    pub requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Server {
    pub fn new(handler: impl Fn(&str) -> String + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(vec![]));
        let recorded = Arc::clone(&requests);
        let stop = Arc::new(AtomicBool::new(false));
        let done = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !done.load(Ordering::Relaxed) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut bytes = Vec::new();
                        let mut buffer = [0; 1024];
                        while !bytes.windows(4).any(|w| w == b"\r\n\r\n") && bytes.len() < 32_768 {
                            let count = stream.read(&mut buffer).unwrap_or(0);
                            if count == 0 {
                                break;
                            }
                            bytes.extend_from_slice(&buffer[..count]);
                        }
                        let request = String::from_utf8_lossy(&bytes).into_owned();
                        recorded.lock().unwrap().push(request.clone());
                        let _ = stream.write_all(handler(&request).as_bytes());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("loopback fixture accept failed: {error}"),
                }
            }
        });
        Self {
            url,
            requests,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

pub fn response(status: &str, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    )
}

pub fn cli(args: &[&str]) -> Output {
    command(args).output().unwrap()
}

pub fn command(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_anatoly"));
    command.args(args);
    command
}

pub fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

static NEXT: AtomicU64 = AtomicU64::new(0);
pub struct Files(Vec<PathBuf>);

impl Files {
    pub fn new() -> Self {
        Self(vec![])
    }
    pub fn path(&mut self, extension: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "anatoly-audit-{}-{}.{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
            extension
        ));
        assert!(!path.exists());
        self.0.push(path.clone());
        path
    }
    pub fn write(&mut self, extension: &str, value: impl AsRef<[u8]>) -> PathBuf {
        let path = self.path(extension);
        fs::write(&path, value).unwrap();
        path
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        for path in &self.0 {
            if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
    }
}
