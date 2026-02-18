use ::snmp::sync::SyncSession;
use ::snmp::*;

/*
cargo run --example query_device_sync --features sync 1.1.1.1:161 public
cargo run --example query_device_sync --features sync,v3 1.1.1.1:161 "v3:username=dave password=secret"
cargo run --example query_device_sync --features sync,v3,localdes 1.1.1.1:161 "v3:username=davex password=secret123 cipher=DES privacy=PrivPass123 auth=authpriv"
*/

fn test() -> SnmpResult<()> {
    let mut device = String::new();
    let mut security = String::new();
    for a in std::env::args().skip(1) {
        if device.is_empty() {
            device = a;
        } else {
            security = a;
        }
    }
    if device.is_empty() || security.is_empty() {
        eprintln!("Command line arguments: <device> <security>");
        eprintln!(" <device> - socketaddress host:port, e.g. 127.0.0.1:161");
        eprintln!(" <security> - community string");
        return Ok(());
    }
    let sec = security.parse()?;
    println!("security {:?}", sec);
    let scka = match device.parse::<std::net::SocketAddr>() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Unable to parse device address: {} - {}", device, e);
            return Ok(());
        }
    };
    let mut sess = SyncSession::new(scka, sec, None, 100)?;
    let pdu = sess.get(&[1u32, 3, 6, 1, 2, 1, 1, 1, 0], 1)?;
    println!("{:?}", pdu);
    let pdu = sess.getbulk(
        [
            [1u32, 3, 6, 1, 2, 1, 1, 5].as_slice(),
            [1u32, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1].as_slice(),
        ],
        1,
        100,
    )?;
    println!("{:?}", pdu);
    Ok(())
}
fn main() {
    if let Err(e) = test() {
        eprintln!("Error: {:?}", e);
    }
}
