use crate::{
    asn1, get_oid_array, pdu, AsnReader, ObjectIdentifier, SnmpError, SnmpMessageType, SnmpResult,
    Value, Varbinds,
};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::num::Wrapping;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{lookup_host, ToSocketAddrs, UdpSocket};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{self, Duration};
const BUFFER_SIZE: usize = 4096;

#[derive(Debug, Clone)]
pub struct SNMPResponse {
    pub varbind_bytes: Vec<u8>,
    pub version: i64,
    pub community: Vec<u8>,
    pub message_type: SnmpMessageType,
    pub req_id: i32,
    pub error_status: u32,
    pub error_index: u32,
    //pub varbinds: crate::Varbinds<'a>,
}
impl SNMPResponse {
    pub fn from_vec(bytes: Vec<u8>) -> SnmpResult<SNMPResponse> {
        let seq = AsnReader::from_bytes(&bytes).read_raw(asn1::TYPE_SEQUENCE)?;
        let mut rdr = AsnReader::from_bytes(seq);
        let version = rdr.read_asn_integer()?;
        if version > 1 || version < 0 {
            return Err(SnmpError::UnsupportedVersion);
        }
        let community = rdr.read_asn_octetstring()?.to_vec();
        let ident = rdr.peek_byte()?;
        let message_type = SnmpMessageType::from_ident(ident)?;

        let mut response_pdu = AsnReader::from_bytes(rdr.read_raw(ident)?);

        let req_id = response_pdu.read_asn_integer()?;
        if req_id < i32::min_value() as i64 || req_id > i32::max_value() as i64 {
            return Err(SnmpError::ValueOutOfRange);
        }

        let error_status = response_pdu.read_asn_integer()?;
        if error_status < 0 || error_status > i32::max_value() as i64 {
            return Err(SnmpError::ValueOutOfRange);
        }

        let error_index = response_pdu.read_asn_integer()?;
        if error_index < 0 || error_index > i32::max_value() as i64 {
            return Err(SnmpError::ValueOutOfRange);
        }

        let varbind_bytes = response_pdu.read_raw(asn1::TYPE_SEQUENCE)?.to_vec();
        //let varbinds = Varbinds::from_bytes(varbind_bytes);
        Ok(SNMPResponse {
            varbind_bytes,
            version,
            community,
            message_type,
            req_id: req_id as i32,
            error_status: error_status as u32,
            error_index: error_index as u32,
        })
    }
    pub fn varbinds(&self) -> Varbinds<'_> {
        Varbinds::from_bytes(&self.varbind_bytes)
    }
    pub fn get_varbind(&self, oid: &[u32]) -> Option<(ObjectIdentifier<'_>, Value<'_>)> {
        Varbinds::from_bytes(&self.varbind_bytes).find(|v| v.0.eq(oid))
    }
}

struct LimitBasket {
    last: Mutex<Instant>,
    cnt: std::sync::atomic::AtomicUsize,
    limit_pps: std::sync::atomic::AtomicUsize,
    minwait_time: Duration,
}
impl LimitBasket {
    fn new(limit_pps: usize) -> LimitBasket {
        LimitBasket {
            last: Mutex::new(Instant::now()),
            cnt: std::sync::atomic::AtomicUsize::new(0),
            limit_pps: std::sync::atomic::AtomicUsize::new(limit_pps),
            minwait_time: Duration::from_millis(10),
        }
    }
    fn set_limit(&self, limit_pps: usize) {
        self.limit_pps
            .store(limit_pps, std::sync::atomic::Ordering::Relaxed);
    }
    async fn shot(&self) {
        let limit_pps = self.limit_pps.load(std::sync::atomic::Ordering::Relaxed);
        if limit_pps == 0 {
            return;
        }
        if self.cnt.load(std::sync::atomic::Ordering::Relaxed) == 0 {
            self.cnt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            *self.last.lock().await = Instant::now();
            return;
        }
        let mut last = self.last.lock().await;
        let mut nw = Instant::now();
        let elapsed = (nw - *last).as_secs_f64();
        let mut sub_pps = ((limit_pps as f64) * elapsed).trunc();
        if sub_pps < 0f64 {
            sub_pps = 0f64;
        }
        let sub_pps = sub_pps as usize;
        if self.cnt.load(std::sync::atomic::Ordering::Relaxed) <= sub_pps {
            self.cnt.store(0, std::sync::atomic::Ordering::Relaxed);
        } else {
            self.cnt
                .fetch_sub(sub_pps, std::sync::atomic::Ordering::Relaxed);
        }
        let cnt = self.cnt.load(std::sync::atomic::Ordering::Relaxed);
        if cnt > 0 {
            let wd = Duration::from_secs_f64((cnt as f64) / (limit_pps as f64) / 10f64);
            if wd >= self.minwait_time {
                tokio::time::sleep(wd).await;
                let nw2 = Instant::now();
                let spent = ((nw2 - nw).as_secs_f64() * (limit_pps as f64)).trunc() as usize;
                if spent >= cnt {
                    self.cnt.store(0, std::sync::atomic::Ordering::Relaxed);
                } else {
                    self.cnt
                        .fetch_sub(spent, std::sync::atomic::Ordering::Relaxed);
                }
                nw = nw2;
            }
        }
        self.cnt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        *last = nw;
    }
}
struct SocketLimit {
    socket: UdpSocket,
    send_limit: LimitBasket,
}
impl SocketLimit {
    pub fn new(socket: UdpSocket) -> SocketLimit {
        SocketLimit {
            socket,
            send_limit: LimitBasket::new(0),
        }
    }
    pub async fn set_send_limit(&self, limit_pps: usize) {
        self.send_limit.set_limit(limit_pps);
    }
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    pub async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }
    pub async fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], target: A) -> std::io::Result<usize> {
        self.send_limit.shot().await;
        self.socket.send_to(buf, target).await
    }
}
pub struct SNMPSession {
    socket: Arc<SocketLimit>,
    community: Vec<u8>,
    req_id: Wrapping<i32>,
    version: i32,
    pub host: SocketAddr,
    rx: Receiver<Vec<u8>>,
    send_pdu: pdu::Buf,
}
impl SNMPSession {
    pub fn host(&self) -> &SocketAddr {
        &self.host
    }
    pub fn set_host(&mut self, new_host: SocketAddr) {
        self.host = new_host;
    }
    pub fn last_req_id(&self) -> i32 {
        self.req_id.0
    }
    pub fn set_last_req_id(&mut self, reqid: i32) {
        self.req_id.0 = reqid;
    }
    pub fn snmp_version(&self) -> i32 {
        self.version
    }
    pub fn set_snmp_version(&mut self, v: i32) -> SnmpResult<()> {
        if v == 1 || v == 2 {
            self.version = v;
            Ok(())
        } else {
            Err(SnmpError::ValueOutOfRange)
        }
    }
    pub fn snmp_community(&self) -> &Vec<u8> {
        &self.community
    }
    pub fn set_snmp_community(&mut self, community: &[u8]) -> SnmpResult<()> {
        if community.is_empty() {
            return Err(SnmpError::CommunityMismatch);
        }
        self.community.resize(community.len(), 0);
        self.community.as_mut_slice().copy_from_slice(community);
        Ok(())
    }
    pub async fn set_send_limit(&self, limit_pps: usize) {
        self.socket.set_send_limit(limit_pps).await;
    }
    async fn send_and_recv(&mut self) -> SnmpResult<SNMPResponse> {
        let _sent_bytes = match self.socket.send_to(&self.send_pdu[..], self.host).await {
            Err(e) => {
                return Err(SnmpError::SendError(format!("{}", e)));
            }
            Ok(sendres) => sendres,
        };
        match self.rx.recv().await {
            None => Err(SnmpError::ReceiveError("Received None".to_string())),
            Some(pdubuf) => Ok(SNMPResponse::from_vec(pdubuf)?),
        }
    }
    async fn send_and_recv_timeout(&mut self, timeout: Duration) -> SnmpResult<SNMPResponse> {
        match time::timeout(timeout, self.send_and_recv()).await {
            Err(_) => Err(SnmpError::Timeout),
            Ok(resio) => resio,
        }
    }
    async fn send_and_recv_repeat(
        &mut self,
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SNMPResponse> {
        for _ in 1..repeat {
            match self.send_and_recv_timeout(timeout).await {
                Err(e) => match e {
                    SnmpError::Timeout => continue,
                    SnmpError::RequestIdMismatch => continue, //late reply
                    other => return Err(other),
                },
                Ok(result) => return Ok(result),
            }
        }
        self.send_and_recv_timeout(timeout).await
    }
    async fn send_and_get(&mut self, repeat: u32, timeout: Duration) -> SnmpResult<SNMPResponse> {
        let req_id = self.req_id.0;
        let rpdu = self.send_and_recv_repeat(repeat, timeout).await?;
        self.req_id += Wrapping(1);
        if rpdu.message_type != SnmpMessageType::Response {
            return Err(SnmpError::AsnWrongType);
        }
        if rpdu.req_id != req_id {
            return Err(SnmpError::RequestIdMismatch);
        }
        if rpdu.community != &self.community[..] {
            return Err(SnmpError::CommunityMismatch);
        }
        Ok(rpdu)
    }
    pub async fn get(
        &mut self,
        name: &[u32],
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SNMPResponse> {
        pdu::build_get(
            self.community.as_slice(),
            self.req_id.0,
            name,
            &mut self.send_pdu,
            self.version,
        );
        self.send_and_get(repeat, timeout).await
    }
    pub async fn getnext(
        &mut self,
        name: &[u32],
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SNMPResponse> {
        pdu::build_getnext(
            self.community.as_slice(),
            self.req_id.0,
            name,
            &mut self.send_pdu,
            self.version,
        );
        self.send_and_get(repeat, timeout).await
    }

    pub async fn getbulk(
        &mut self,
        names: &[&[u32]],
        non_repeaters: u32,
        max_repetitions: u32,
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SNMPResponse> {
        pdu::build_getbulk(
            self.community.as_slice(),
            self.req_id.0,
            names,
            non_repeaters,
            max_repetitions,
            &mut self.send_pdu,
        );
        self.send_and_get(repeat, timeout).await
    }

    /// # Panics if any of the values are not one of these supported types:
    ///   - `Boolean`
    ///   - `Null`
    ///   - `Integer`
    ///   - `OctetString`
    ///   - `ObjectIdentifier`
    ///   - `IpAddress`
    ///   - `Counter32`
    ///   - `Unsigned32`
    ///   - `Timeticks`
    ///   - `Opaque`
    ///   - `Counter64`
    pub async fn set(
        &mut self,
        values: &[(&[u32], Value<'_>)],
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SNMPResponse> {
        pdu::build_set(
            self.community.as_slice(),
            self.req_id.0,
            values,
            &mut self.send_pdu,
            self.version,
        );
        self.send_and_get(repeat, timeout).await
    }
    pub async fn get_oid(
        &mut self,
        oid: &str,
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SNMPResponse> {
        self.get(get_oid_array(oid).as_slice(), repeat, timeout)
            .await
    }
    pub async fn get_oid_next(
        &mut self,
        oid: &str,
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SNMPResponse> {
        self.getnext(get_oid_array(oid).as_slice(), repeat, timeout)
            .await
    }
}
#[derive(Clone)]
struct SNMPSocketInner {
    socket: Arc<SocketLimit>,
    sessions: Arc<RwLock<BTreeMap<SocketAddr, Sender<Vec<u8>>>>>,
}
impl SNMPSocketInner {
    async fn new() -> std::io::Result<Self> {
        let socket = UdpSocket::bind((std::net::Ipv4Addr::new(0, 0, 0, 0), 0)).await?;
        Ok(Self {
            socket: Arc::new(SocketLimit::new(socket)),
            sessions: Arc::new(RwLock::new(BTreeMap::new())),
        })
    }
    fn from_socket(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(SocketLimit::new(socket)),
            sessions: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }
    async fn clear_closed_sessions(&self) -> usize {
        let mut grd = self.sessions.write().await;
        grd.retain(|_k, v| !v.is_closed());
        grd.len()
    }
    async fn run(&self) {
        trace!("receive task started");
        self.clear_closed_sessions().await;
        let mut buf = Vec::<u8>::new();
        buf.resize(BUFFER_SIZE, 0);
        let mbuf = buf.as_mut_slice();
        loop {
            if self.recv_one(mbuf).await.is_err() {
                break;
            }
        }
        self.clear_closed_sessions().await;
        trace!("receive task finished");
    }
    async fn recv_one(&self, buf: &mut [u8]) -> std::io::Result<()> {
        let (len, addr) = self.socket.recv_from(buf).await?;
        let res = match self.sessions.read().await.get(&addr) {
            None => {
                warn!("Unknown host {:?} - {} bytes received from", addr, len);
                return Ok(());
            }
            Some(tx) => tx.try_send(buf[0..len].to_vec()),
        };
        if let Err(e) = res {
            warn!("Warning: SNMP error pass response to {}: {}", addr, e);
            if self.clear_closed_sessions().await < 1 {
                //stop receive task
                trace!("No more sessions, closing receive task");
                return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
            }
        };
        Ok(())
    }
}
#[derive(Clone)]
pub struct SNMPSocket {
    inner: SNMPSocketInner,
    recv_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl SNMPSocket {
    pub async fn new() -> std::io::Result<Self> {
        Ok(Self {
            inner: SNMPSocketInner::new().await?,
            recv_task: Arc::new(Mutex::new(None)),
        })
    }
    pub async fn set_send_limit(&self, limit_pps: usize) {
        self.inner.socket.set_send_limit(limit_pps).await;
    }
    pub fn from_socket(socket: UdpSocket) -> Self {
        Self {
            inner: SNMPSocketInner::from_socket(socket),
            recv_task: Arc::new(Mutex::new(None)),
        }
    }
    pub async fn session<SA: ToSocketAddrs>(
        &self,
        hostaddr: SA,
        community: &[u8],
        starting_req_id: i32,
        version: i32,
    ) -> std::io::Result<SNMPSession> {
        let la = self.inner.socket.local_addr()?;
        let socketaddr = match lookup_host(&hostaddr)
            .await?
            .find(|a| (a.is_ipv4() && la.is_ipv4()) || (a.is_ipv6() && la.is_ipv6()))
        {
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "Lookup",
                ))
            }
            Some(a) => a,
        };
        if let Some(sess) = self.inner.sessions.read().await.get(&socketaddr) {
            if !sess.is_closed() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "Session already exists",
                ));
            }
        }
        let (tx, rx) = channel(100);
        self.inner.sessions.write().await.insert(socketaddr, tx);
        {
            let recv_task = self.recv_task.clone();
            let mut rt_g = self.recv_task.lock().await;
            let inner = self.inner.clone();
            if rt_g.is_none() {
                *rt_g = Some(tokio::spawn(async move {
                    inner.run().await;
                    recv_task.lock().await.take();
                }));
            }
        }
        Ok(SNMPSession {
            socket: self.inner.socket.clone(),
            community: community.to_vec(),
            req_id: Wrapping(starting_req_id),
            version,
            host: socketaddr,
            rx,
            send_pdu: pdu::Buf::default(),
        })
    }
}
