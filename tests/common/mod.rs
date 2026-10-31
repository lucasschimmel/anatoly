use anatoly::http::Limits;
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
pub struct Server {
    pub url: String,
    pub paths: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Server {
    pub fn new(handler: impl Fn(&str) -> String + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let paths = Arc::new(Mutex::new(vec![]));
        let seen = Arc::clone(&paths);
        let stop = Arc::new(AtomicBool::new(false));
        let done = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            while !done.load(Ordering::Relaxed) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut request = Vec::new();
                        let mut chunk = [0; 1024];
                        while !request.windows(4).any(|w| w == b"\r\n\r\n") && request.len() < 8192
                        {
                            let size = stream.read(&mut chunk).unwrap_or(0);
                            if size == 0 {
                                break;
                            }
                            request.extend_from_slice(&chunk[..size]);
                        }
                        let text = String::from_utf8_lossy(&request);
                        let path = text.split_whitespace().nth(1).unwrap_or("/");
                        seen.lock().unwrap().push(path.to_string());
                        let response = handler(path);
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                }
            }
        });
        Self {
            url,
            paths,
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

pub fn limits() -> Limits {
    Limits {
        timeout: Duration::from_secs(5),
        max_requests: 4,
        max_body: 4096,
        delay: Duration::ZERO,
    }
}
