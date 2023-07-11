use buf_list::BufList;
use bytes::BytesMut;
use memchr::memmem;
use sha2::Digest;
use sha2::Sha256;
use std::env;
use std::io;
use std::io::Read;
use std::io::Write;
use std::mem;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use url::Url;

fn spin_forever(counter: Arc<AtomicU64>) -> ! {
    while counter.fetch_add(1, Ordering::Relaxed) < u64::MAX {}
    panic!("counted to u64::MAX ?!");
}

fn main() {
    let nspinners = env::var("NSPIN")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or_else(|| {
            println!("env var NSPIN not set; creating 8 spinning threads");
            8
        });
    let counter = Arc::new(AtomicU64::new(0));
    for _ in 0..nspinners {
        let counter = Arc::clone(&counter);
        thread::spawn(|| spin_forever(counter));
    }

    let nworkers = env::var("NWORKER")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or_else(|| {
            println!("env var NWORKER not set; creating 1 downloading thread");
            1
        });

    let url = env::args().nth(1).expect("need url as first arg");
    let url = Url::parse(&url).expect("first arg is not a url");
    let addr = url
        .socket_addrs(|| Some(80))
        .expect("could not get socket addrs")
        .get(0)
        .copied()
        .expect("empty addrs");

    let mut worker_threads = Vec::new();
    for _ in 0..nworkers {
        let url = url.clone();
        worker_threads.push(thread::spawn(move || download_thread(url, addr)));
    }

    for t in worker_threads {
        t.join().unwrap();
    }
}

fn download_thread(url: Url, addr: SocketAddr) {
    loop {
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let hashing_thread = thread::spawn(move || {
            let mut accum = BufList::new();
            let mut n = 0;
            while let Ok(chunk) = rx.recv() {
                n += chunk.len();
                if !chunk.is_empty() {
                    if chunk.iter().all(|&x| x == 0) {
                        println!("hashing thread: rx all 0 chunk at offset {n}");
                    }
                    accum.push_chunk(&*chunk);
                }
            }
            let mut hasher = Sha256::default();
            let mut n = 0;
            for chunk in accum.iter() {
                if chunk.iter().all(|&x| x == 0) {
                    println!("hashing thread: hashing all 0 chunk at offset {n}");
                }
                n += chunk.len();
                hasher.update(chunk);
            }
            println!("read {n} bytes; hash={:x}", hasher.finalize());
        });

        println!("connecting to = {addr}");
        let mut stream = TcpStream::connect(addr).expect("could not connect");
        let get = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\n\r\n",
            url.path(),
            url.host().unwrap(),
        );
        write!(stream, "{get}").expect("write GET ... failed");
        stream.flush().expect("failed to flush");
        stream.set_nonblocking(true).expect("failed to set nonblocking");

        let finder = memmem::Finder::new(b"\r\n");
        let mut leftovers = Vec::new();
        let mut buf = vec![0; 1 << 20];

        // read headers
        let mut done_with_headers = false;
        let mut content_length = None;
        while !done_with_headers {
            match stream.read(&mut buf) {
                Ok(0) => {
                    println!("0-length read; done");
                    break;
                }
                Ok(n) => {
                    leftovers.extend_from_slice(&buf[..n]);
                    while let Some(i) = finder.find(&leftovers) {
                        if i == 0 {
                            leftovers.drain(..2);
                            done_with_headers = true;
                            break;
                        }
                        let header = String::from_utf8_lossy(&leftovers[..i]);
                        if let Some(length) =
                            header.strip_prefix("content-length: ")
                        {
                            content_length = length.parse::<usize>().ok();
                        }
                        leftovers.drain(..i + 2);
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::yield_now();
                }
                Err(err) => panic!("read failed: {err}"),
            }
        }

        let content_length =
            content_length.expect("did not find content-length header");
        let mut nread = leftovers.len();
        tx.send(leftovers).unwrap();
        while nread < content_length {
            match stream.read(&mut buf) {
                Ok(0) => {
                    println!("0-length read; done");
                    break;
                }
                Ok(n) => {
                    let buf = &buf[..n];
                    if buf.iter().copied().all(|x| x == 0) {
                        eprintln!(
                            "FOUND ALL ZERO CHUNK offset={nread} len={n}"
                        );
                        panic!("die die die");
                    }
                    nread += n;
                    tx.send(buf.to_vec()).unwrap();
                    thread::yield_now();
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::yield_now();
                }
                Err(err) => panic!("read failed: {err}"),
            }
        }
        mem::drop(tx);
        hashing_thread.join().unwrap();
    }
}
