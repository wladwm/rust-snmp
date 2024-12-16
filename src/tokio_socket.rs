use crate::{
    asn1, get_oid_array, pdu, AsnReader, ObjectIdentifier, SnmpError, SnmpMessageType, SnmpResult,
    Value, Varbinds,
};

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::num::Wrapping;
use std::sync::Arc;
use std::sync::{Mutex, RwLock};
use std::time::Instant;
use tokio::net::{lookup_host, ToSocketAddrs, UdpSocket};
use tokio::sync::mpsc::{channel, Receiver, Sender};
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
    last: tokio::sync::Mutex<(Instant, usize)>,
    limit_pps: std::sync::atomic::AtomicUsize,
}
impl LimitBasket {
    fn new(limit_pps: usize) -> LimitBasket {
        LimitBasket {
            last: tokio::sync::Mutex::new((Instant::now(), 0)),
            limit_pps: std::sync::atomic::AtomicUsize::new(limit_pps),
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
        let mut last = self.last.lock().await;
        if last.1 == 0 {
            last.1 = 1;
            last.0 = Instant::now();
            return;
        }
        let mut nw = Instant::now();
        let elapsed = (nw - last.0).as_secs_f64();
        let mut sub_pps = ((limit_pps as f64) * elapsed).trunc();
        if sub_pps < 0f64 {
            sub_pps = 0f64;
        }
        let sub_pps = sub_pps as usize;
        if last.1 <= sub_pps {
            last.1 = 0;
        } else {
            last.1 -= sub_pps;
        }
        if last.1 >= (limit_pps / 1000) {
            let wd = Duration::from_secs_f64((last.1 as f64) / (limit_pps as f64));
            tokio::time::sleep(wd).await;
            let nw2 = Instant::now();
            let spent = ((nw2 - nw).as_secs_f64() * (limit_pps as f64)).trunc() as usize;
            if spent >= last.1 {
                last.1 = 0;
            } else {
                last.1 -= spent;
            }
            nw = nw2;
        }
        last.1 += 1;
        last.0 = nw;
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
    need_reqid: Arc<std::sync::atomic::AtomicI32>,
    rx: Receiver<SNMPResponse>,
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
    async fn send_and_recv_timeout(&mut self, timeout: Duration) -> SnmpResult<SNMPResponse> {
        let _sent_bytes = match self.socket.send_to(&self.send_pdu[..], self.host).await {
            Err(e) => {
                return Err(SnmpError::SendError(format!("{}", e)));
            }
            Ok(sendres) => sendres,
        };
        match time::timeout(timeout, self.rx.recv()).await {
            Err(_) => Err(SnmpError::Timeout),
            Ok(resio) => match resio {
                None => Err(SnmpError::ReceiveError("Received None".to_string())),
                Some(pdubuf) => Ok(pdubuf),
            },
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
        self.need_reqid
            .store(req_id, std::sync::atomic::Ordering::Relaxed);
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
    pub async fn getmulti(
        &mut self,
        names: &[&[u32]],
        repeat: u32,
        timeout: Duration,
    ) -> SnmpResult<SNMPResponse> {
        pdu::build_getmulti(
            self.community.as_slice(),
            self.req_id.0,
            names,
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

struct SNMPSessionBack {
    reqid: Arc<std::sync::atomic::AtomicI32>,
    txresp: Sender<SNMPResponse>,
}
impl SNMPSessionBack {
    fn new(
        reqid: Arc<std::sync::atomic::AtomicI32>,
        txresp: Sender<SNMPResponse>,
    ) -> SNMPSessionBack {
        SNMPSessionBack { reqid, txresp }
    }
}
enum SNMPSessionBacks {
    Few(SNMPSessionBack),
    Many(Vec<SNMPSessionBack>),
}
impl SNMPSessionBacks {
    fn new(
        reqid: Arc<std::sync::atomic::AtomicI32>,
        txresp: Sender<SNMPResponse>,
    ) -> SNMPSessionBacks {
        SNMPSessionBacks::Few(SNMPSessionBack::new(reqid, txresp))
    }
    fn push(&mut self, reqid: Arc<std::sync::atomic::AtomicI32>, txresp: Sender<SNMPResponse>) {
        let b = SNMPSessionBack::new(reqid, txresp);
        if let SNMPSessionBacks::Many(m) = self {
            m.push(b);
            return;
        }
        let mut old = SNMPSessionBacks::Many(vec![b]);
        std::mem::swap(self, &mut old);
        if let (SNMPSessionBacks::Many(m), SNMPSessionBacks::Few(o)) = (self, old) {
            m.push(o);
        }
    }
    fn len(&self) -> usize {
        match self {
            SNMPSessionBacks::Few(_) => 1,
            SNMPSessionBacks::Many(m) => m.len(),
        }
    }
    fn is_empty(&self) -> bool {
        match self {
            SNMPSessionBacks::Few(_) => false,
            SNMPSessionBacks::Many(m) => m.is_empty(),
        }
    }
    fn iter<'a>(&'a self) -> std::slice::Iter<'a, SNMPSessionBack> {
        match self {
            SNMPSessionBacks::Many(m) => m.iter(),
            SNMPSessionBacks::Few(o) => std::slice::from_ref(o).iter(),
        }
    }
    /*
    fn iter_mut<'a>(&'a mut self) -> std::slice::IterMut<'a, SNMPSessionBack> {
        match self {
            SNMPSessionBacks::Many(m) => m.iter_mut(),
            SNMPSessionBacks::Few(o) => std::slice::from_mut(o).iter_mut(),
        }
    }
    */
    fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&SNMPSessionBack) -> bool,
    {
        match self {
            SNMPSessionBacks::Many(m) => m.retain(f),
            SNMPSessionBacks::Few(o) => {
                if !f(o) {
                    *self = SNMPSessionBacks::Many(Vec::new());
                }
            }
        }
    }
}
#[derive(Clone)]
struct SNMPSocketInner {
    socket: Arc<SocketLimit>,
    sessions: Arc<RwLock<BTreeMap<SocketAddr, SNMPSessionBacks>>>,
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
        let mut grd = self.sessions.write().unwrap();
        grd.iter_mut().for_each(|(_, vc)| {
            vc.retain(|c| !c.txresp.is_closed());
        });
        grd.retain(|_k, v| !v.is_empty());
        grd.len()
    }
    async fn run(&self) {
        trace!("receive task started");
        self.clear_closed_sessions().await;
        let mut buf = Vec::<u8>::new();
        buf.resize(BUFFER_SIZE, 0);
        let mbuf = buf.as_mut_slice();
        loop {
            if let Err(e) = self.recv_one(mbuf).await {
                trace!("receive task error: {}", e);
                break;
            }
        }
        self.clear_closed_sessions().await;
        trace!("receive task finished");
    }
    async fn recv_one(&self, buf: &mut [u8]) -> std::io::Result<()> {
        let (len, addr) = self.socket.recv_from(buf).await?;

        let res = match self.sessions.read().unwrap().get(&addr) {
            None => {
                warn!("Unknown host {:?} - {} bytes received from", addr, len);
                return Ok(());
            }
            Some(clts) => {
                let rsp = match SNMPResponse::from_vec(buf[0..len].to_vec()) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("Snmp error {:?} from {} len {}", e, addr, len);
                        return Ok(());
                    }
                };
                if clts.len() == 1 {
                    let c = clts.iter().next().unwrap();
                    c.txresp.try_send(rsp)
                } else {
                    match clts
                        .iter()
                        .find(|c| c.reqid.load(std::sync::atomic::Ordering::Relaxed) == rsp.req_id)
                    {
                        Some(c) => c.txresp.try_send(rsp),
                        None => return Ok(()), //Err(tokio::sync::mpsc::error::TrySendError::Closed(rsp)),
                    }
                }
            }
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
        mut starting_req_id: i32,
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
        let mut sess = self.inner.sessions.write().unwrap();
        let (tx, rx) = channel(100);
        let nreqid = Arc::new(std::sync::atomic::AtomicI32::new(0));
        if sess.get(&socketaddr).is_none() {
            sess.insert(socketaddr, SNMPSessionBacks::new(nreqid.clone(), tx));
        } else {
            let lng = sess.get(&socketaddr).unwrap().len();
            if starting_req_id < 2 && lng > 0 {
                starting_req_id = (lng * 100) as i32;
            };
            sess.get_mut(&socketaddr).unwrap().push(nreqid.clone(), tx);
        }
        {
            let recv_task = self.recv_task.clone();
            let mut rt_g = self.recv_task.lock().unwrap();
            let inner = self.inner.clone();
            if rt_g.is_none() {
                *rt_g = Some(tokio::spawn(async move {
                    inner.run().await;
                    recv_task.lock().unwrap().take();
                }));
            }
        }
        Ok(SNMPSession {
            socket: self.inner.socket.clone(),
            community: community.to_vec(),
            req_id: Wrapping(starting_req_id),
            need_reqid: nreqid,
            version,
            host: socketaddr,
            rx,
            send_pdu: pdu::Buf::default(),
        })
    }
}
