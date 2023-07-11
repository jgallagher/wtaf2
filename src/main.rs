use buf_list::BufList;
use bytes::BytesMut;
use memchr::memmem;
use sha2::Digest;
use sha2::Sha256;
use std::env;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use url::Url;

fn main() {
    let mut args = env::args();
    _ = args.next(); // skip argv[0]
    let url = args.next().expect("need url as arg 1");
    let url = Url::parse(&url).expect("first arg is not a url");
    let addr = url
        .socket_addrs(|| Some(80))
        .expect("could not get socket addrs")
        .get(0)
        .copied()
        .expect("empty addrs");

    let correct_data_path = args.next().expect("need expected file as arg 2");
    let correct_data =
        fs::read(&correct_data_path).expect("failed to read correct data");

    let balloon_size = args
        .next()
        .expect("need balloon size as arg 3")
        .parse::<usize>()
        .expect("failed to parse balloon size");
    let balloon = vec![1; balloon_size];
    println!("balloon start={:?} end={:?}", balloon.as_ptr(), unsafe {
        balloon.as_ptr().add(balloon_size)
    });

    loop {
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
                    panic!("0-length read");
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

        // ensure we found the content length
        let content_length =
            content_length.expect("did not find content-length header");

        // start accumulating the full file with whatever is left from the last
        // chunk containing the final header separator
        let mut accum = BufList::new();
        let mut nread = buf.len();
        accum.push_chunk(buf.split_to(nread));

        while nread < content_length {
            match read_into(&mut buf, &mut stream) {
                Ok(0) => {
                    panic!("0-length read");
                }
                Ok(n) => {
                    if buf != correct_data[nread..][..n] {
                        println!(
                            "INCORRECT CHUNK offset={nread:#x} len={n} addr={:?}", buf.as_ptr()
                        );
                        for i in 0..n {
                            println!(
                                "offset={:#10x} expected={:02x} got={:02x}",
                                nread + i,
                                correct_data[nread + i],
                                buf[i]
                            );
                        }
                    }
                    nread += n;
                    accum.push_chunk(buf.split_to(n));
                }
                Err(err) => panic!("read failed: {err}"),
            }
        }

        let mut hasher = Sha256::new();
        for chunk in accum.iter() {
            hasher.update(chunk);
        }
        println!(
            "read {} bytes; hash={:x}",
            accum.num_bytes(),
            hasher.finalize()
        );
    }
}

fn read_into(buf: &mut BytesMut, sock: &mut TcpStream) -> io::Result<usize> {
    let orig_len = buf.len();

    // grow an extra 128 KiB
    buf.resize(orig_len + (128 << 10), 0);

    let n = sock.read(&mut buf[orig_len..])?;

    // trim off any extra that wasn't written into
    buf.truncate(orig_len + n);

    Ok(n)
}
