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
use std::mem::MaybeUninit;
use std::net::TcpStream;
use std::sync::mpsc;
use std::thread;
use url::Url;

fn main() {
    let mut args = env::args();
    _ = args.next(); // skip argv[0]
    let url = args.next().expect("need url as first arg");
    let url = Url::parse(&url).expect("first arg is not a url");
    let addr = url
        .socket_addrs(|| Some(80))
        .expect("could not get socket addrs")
        .get(0)
        .copied()
        .expect("empty addrs");

    let balloon_size = args
        .next()
        .expect("need balloon size as second arg")
        .parse::<usize>()
        .expect("failed to parse balloon size");
    let balloon = vec![1; balloon_size];
    println!("balloon start={:?} end={:?}", balloon.as_ptr(), unsafe {
        balloon.as_ptr().add(balloon_size)
    });

    loop {
        let (tx, rx) = mpsc::channel::<BytesMut>();
        let hashing_thread = thread::spawn(move || {
            let mut accum = BufList::new();
            let mut n = 0;
            while let Ok(chunk) = rx.recv() {
                n += chunk.len();
                if !chunk.is_empty() {
                    if chunk.iter().all(|&x| x == 0) {
                        println!(
                            "hashing thread: rx all 0 chunk at offset {n}"
                        );
                    }
                    accum.push_chunk(&*chunk);
                }
            }
            let mut hasher = Sha256::default();
            let mut n = 0;
            for chunk in accum.iter() {
                if chunk.iter().all(|&x| x == 0) {
                    println!(
                        "hashing thread: hashing all 0 chunk at offset {n}"
                    );
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

        let finder = memmem::Finder::new(b"\r\n");
        let mut buf = BytesMut::new();

        // read headers
        let mut done_with_headers = false;
        let mut content_length = None;
        while !done_with_headers {
            match read_into(&mut buf, &mut stream) {
                Ok(0) => {
                    println!("0-length read; done");
                    break;
                }
                Ok(_n) => {
                    while let Some(i) = finder.find(&buf) {
                        if i == 0 {
                            _ = buf.split_to(2);
                            done_with_headers = true;
                            break;
                        }
                        let header = String::from_utf8_lossy(&buf[..i]);
                        if let Some(length) =
                            header.strip_prefix("content-length: ")
                        {
                            content_length = length.parse::<usize>().ok();
                        }
                        _ = buf.split_to(i + 2);
                    }
                }
                Err(err) => panic!("read failed: {err}"),
            }
        }

        let content_length =
            content_length.expect("did not find content-length header");
        let mut nread = buf.len();
        tx.send(buf.split_to(nread)).unwrap();
        while nread < content_length {
            match read_into(&mut buf, &mut stream) {
                Ok(0) => {
                    println!("0-length read; done");
                    break;
                }
                Ok(n) => {
                    if buf.iter().copied().take(n).all(|x| x == 0) {
                        eprintln!(
                            "FOUND ALL ZERO CHUNK offset={nread:#x} len={n} addr={:?}", buf.as_ptr()
                        );
                        panic!("die die die");
                    }
                    nread += n;
                    tx.send(buf.split_to(n)).unwrap();
                }
                Err(err) => panic!("read failed: {err}"),
            }
        }
        mem::drop(tx);
        hashing_thread.join().unwrap();
    }
}

fn read_into(buf: &mut BytesMut, sock: &mut TcpStream) -> io::Result<usize> {
    if buf.spare_capacity_mut().is_empty() {
        buf.reserve(128 << 10);
        assert!(!buf.spare_capacity_mut().is_empty());
    }

    let orig_len = buf.len();
    unsafe {
        let b = &mut *(buf.spare_capacity_mut() as *mut [MaybeUninit<u8>]
            as *mut [u8]);

        let nread = sock.read(b)?;
        buf.set_len(orig_len + nread);
        Ok(nread)
    }
}
