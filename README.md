## At first I just thought I will use a ping library for my next project. but since i absolutely hate using pre-made libraries. This is what i got!

### Note: I might got a few thigns wrong about the packet size


### Usage:

```
mod ping;
use std::{net::IpAddr, str::FromStr, thread, time};

fn main() {
    let mut pinger = ping::Pinger::new(
        IpAddr::from_str("1.1.1.1").unwrap(),
        time::Duration::from_millis(500),
        46,
        60
    );
    loop {
        match pinger.ping_throw() {
            Ok(echo) => {
                println!(
                    "{} bytes from {}; icmp_seq={}, rtt={} ns, avg_rtt={} ns ",
                    echo.packet_size(),
                    echo.s_addr(),
                    pinger.icmp_seq(),
                    echo.rtt().as_nanos(),
                    pinger.avg_rtt().as_nanos()
                )
            }
            Err(e) => {
                eprintln!("{e}")
            }
        }
        thread::sleep(time::Duration::from_millis(1000));
    }
}


```