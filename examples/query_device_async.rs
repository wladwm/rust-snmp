use ::snmp::tokio_socket::*;
use ::snmp::*;

/*
cargo run --example query_device_async --features async 1.1.1.1:161 public
cargo run --example query_device_async --features async,v3 1.1.1.1:161 "v3:username=dave password=secret"
cargo run --example query_device_async --features async,v3,localdes 1.1.1.1:161 "v3:username=davex password=secret123 cipher=DES privacy=PrivPass123 auth=authpriv"
*/

fn print_vars(rsp: &SnmpOwnedPdu) {
    let vbs = rsp.varbinds();
    for (oid, v) in vbs {
        println!("{}\t{}", oid, v);
    }
}

async fn test(device: &str, security: &str) -> SnmpResult<()> {
    let socket = SNMPSocket::new().await?;
    let sec = security.parse()?;
    println!("security {:?}", sec);
    let scka = match device.parse::<std::net::SocketAddr>() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Unable to parse device address: {} - {}", device, e);
            return Ok(());
        }
    };
    let mut sess = socket.session(scka, sec, 100).await?;
    let timeout = std::time::Duration::from_secs(10);
    println!("sysDescr");
    let pdu = sess
        .get::<&[u32], &[u32]>(&[1u32, 3, 6, 1, 2, 1, 1, 1, 0][..], 1, timeout)
        .await?;
    println!("{:?}", pdu);
    print_vars(&pdu);
    println!("sysName+ifName");
    let pdu = sess
        .getbulk::<&[u32], &[u32], _>(
            [
                [1u32, 3, 6, 1, 2, 1, 1, 5].as_slice(),
                [1u32, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1].as_slice(),
            ],
            1,
            100,
            1,
            timeout,
        )
        .await?;
    println!("{:?}", pdu);
    print_vars(&pdu);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    if let Err(e) = test(&device, &security).await {
        eprintln!("Error: {:?}", e);
    }
    Ok(())
}
