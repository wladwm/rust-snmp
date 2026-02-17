use super::{asn1, snmp, SnmpCredentials, SnmpSecurity, Value, VarbindOid, SnmpResult, BUFFER_SIZE};
use std::{fmt, mem, ops, ptr};

pub struct Buf {
    len: usize,
    buf: [u8; BUFFER_SIZE],
}

impl fmt::Debug for Buf {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_list().entries(&self[..]).finish()
    }
}

impl Default for Buf {
    fn default() -> Buf {
        Buf {
            len: 0,
            // buf: unsafe { mem::uninitialized() },
            buf: {
                let mut buf: [std::mem::MaybeUninit<u8>; BUFFER_SIZE] =
                    unsafe { std::mem::MaybeUninit::uninit().assume_init() };
                for elem in &mut buf[..] {
                    unsafe {
                        std::ptr::write(elem.as_mut_ptr(), 0);
                    }
                }
                unsafe { std::mem::transmute::<_, [u8; BUFFER_SIZE]>(buf) }
            },
        }
    }
}

impl ops::Deref for Buf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf[BUFFER_SIZE - self.len..]
    }
}
impl ops::DerefMut for Buf {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf[BUFFER_SIZE - self.len..]
    }
}

impl Buf {
    pub(crate) fn available(&mut self) -> &mut [u8] {
        &mut self.buf[..(BUFFER_SIZE - self.len)]
    }

    pub(crate) fn push_chunk(&mut self, chunk: &[u8]) {
        let offset = BUFFER_SIZE - self.len;
        self.buf[(offset - chunk.len())..offset].copy_from_slice(chunk);
        self.len += chunk.len();
    }

    pub(crate) fn push_byte(&mut self, byte: u8) {
        self.buf[BUFFER_SIZE - self.len - 1] = byte;
        self.len += 1;
    }

    pub(crate) fn reset(&mut self) {
        self.len = 0;
    }

    pub(crate) fn scribble_bytes<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut [u8]) -> usize,
    {
        let scribbled = f(self.available());
        self.len += scribbled;
    }

    pub(crate) fn push_constructed<F>(&mut self, ident: u8, f: F)
    where
        F: FnOnce(&mut Self),
    {
        let before_len = self.len;
        f(self);
        let written = self.len - before_len;
        self.push_length(written);
        self.push_byte(ident);
    }

    pub(crate) fn push_sequence<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Self),
    {
        self.push_constructed(asn1::TYPE_SEQUENCE, f)
    }

    // fn push_set<F>(&mut self, f: F)
    //     where F: FnMut(&mut Self)
    // {
    //     self.push_constructed(asn1::TYPE_SET, f)
    // }

    pub(crate) fn push_length(&mut self, len: usize) {
        if len < 128 {
            // short form
            self.push_byte(len as u8);
        } else {
            // long form
            let num_leading_nulls = (len.leading_zeros() / 8) as usize;
            let length_len = mem::size_of::<usize>() - num_leading_nulls;
            let leading_byte = length_len as u8 | 0b1000_0000;
            self.scribble_bytes(|o| {
                assert!(o.len() >= length_len + 1);
                let bytes = len.to_be_bytes();
                let write_offset = o.len() - length_len - 1;
                o[write_offset] = leading_byte;
                o[write_offset + 1..].copy_from_slice(&bytes[num_leading_nulls..]);
                length_len + 1
            });
        }
    }

    pub(crate) fn push_integer(&mut self, n: i64) {
        let len = self.push_i64(n);
        self.push_length(len);
        self.push_byte(asn1::TYPE_INTEGER);
    }

    pub(crate) fn push_endofmibview(&mut self) {
        self.push_chunk(&[snmp::SNMP_ENDOFMIBVIEW, 0]);
    }

    pub(crate) fn push_nosuchobject(&mut self) {
        self.push_chunk(&[snmp::SNMP_NOSUCHOBJECT, 0]);
    }

    pub(crate) fn push_nosuchinstance(&mut self) {
        self.push_chunk(&[snmp::SNMP_NOSUCHINSTANCE, 0]);
    }

    pub(crate) fn push_counter32(&mut self, n: u32) {
        let len = self.push_i64(n as i64);
        self.push_length(len);
        self.push_byte(snmp::TYPE_COUNTER32);
    }

    pub(crate) fn push_unsigned32(&mut self, n: u32) {
        let len = self.push_i64(n as i64);
        self.push_length(len);
        self.push_byte(snmp::TYPE_UNSIGNED32);
    }

    pub(crate) fn push_timeticks(&mut self, n: u32) {
        let len = self.push_i64(n as i64);
        self.push_length(len);
        self.push_byte(snmp::TYPE_TIMETICKS);
    }

    pub(crate) fn push_opaque(&mut self, bytes: &[u8]) {
        self.push_chunk(bytes);
        self.push_length(bytes.len());
        self.push_byte(snmp::TYPE_OPAQUE);
    }

    pub(crate) fn push_counter64(&mut self, n: u64) {
        let len = self.push_i64(n as i64);
        self.push_length(len);
        self.push_byte(snmp::TYPE_COUNTER64);
    }

    pub(crate) fn push_i64(&mut self, mut n: i64) -> usize {
        let (null, num_null_bytes) = if !n.is_negative() {
            (0x00u8, (n.leading_zeros() / 8) as usize)
        } else {
            (0xffu8, ((!n).leading_zeros() / 8) as usize)
        };
        n = n.to_be();
        let count = unsafe {
            let wbuf = self.available();
            let mut src_ptr = &n as *const i64 as *const u8;
            let mut dst_ptr = wbuf
                .as_mut_ptr()
                .offset((wbuf.len() - mem::size_of::<i64>()) as isize);
            let mut count = mem::size_of::<i64>() - num_null_bytes;
            if count == 0 {
                count = 1;
            }
            // preserve sign
            if (*(src_ptr.offset((mem::size_of::<i64>() - count) as isize)) ^ null) > 127u8 {
                count += 1;
            }
            assert!(wbuf.len() >= count);
            let offset = (mem::size_of::<i64>() - count) as isize;
            src_ptr = src_ptr.offset(offset);
            dst_ptr = dst_ptr.offset(offset);
            ptr::copy_nonoverlapping(src_ptr, dst_ptr, count);
            count
        };
        self.len += count;
        count
    }

    pub(crate) fn push_boolean(&mut self, boolean: bool) {
        if boolean {
            self.push_byte(0x1);
        } else {
            self.push_byte(0x0);
        }
        self.push_length(1);
        self.push_byte(asn1::TYPE_BOOLEAN);
    }

    pub(crate) fn push_ipaddress(&mut self, ip: &[u8; 4]) {
        self.push_chunk(ip);
        self.push_length(ip.len());
        self.push_byte(snmp::TYPE_IPADDRESS);
    }

    pub(crate) fn push_null(&mut self) {
        self.push_chunk(&[asn1::TYPE_NULL, 0]);
    }

    pub(crate) fn push_object_identifier_raw(&mut self, input: &[u8]) {
        self.push_chunk(input);
        self.push_length(input.len());
        self.push_byte(asn1::TYPE_OBJECTIDENTIFIER);
    }

    pub fn push_object_identifier(&mut self, input: &[u32]) {
        assert!(input.len() >= 2);
        let length_before = self.len;

        self.scribble_bytes(|output| {
            let mut pos = output.len() - 1;
            let (head, tail) = input.split_at(2);
            assert!(head[0] < 3 && head[1] < 40);

            // encode the subids in reverse order
            for subid in tail.iter().rev() {
                let mut subid = *subid;
                let mut last_byte = true;
                loop {
                    assert!(pos != 0);
                    if last_byte {
                        // continue bit is cleared
                        output[pos] = (subid & 0b01111111) as u8;
                        last_byte = false;
                    } else {
                        // continue bit is set
                        output[pos] = (subid | 0b10000000) as u8;
                    }
                    pos -= 1;
                    subid >>= 7;

                    if subid == 0 {
                        break;
                    }
                }
            }

            // encode the head last
            output[pos] = (head[0] * 40 + head[1]) as u8;
            output.len() - pos
        });
        let length_after = self.len;
        self.push_length(length_after - length_before);
        self.push_byte(asn1::TYPE_OBJECTIDENTIFIER);
    }

    pub(crate) fn push_octet_string(&mut self, bytes: &[u8]) {
        self.push_chunk(bytes);
        self.push_length(bytes.len());
        self.push_byte(asn1::TYPE_OCTETSTRING);
    }
}

pub(crate) fn push_varbinds_raw<'c, 'b: 'c, VLS, OBJNM, VL>(buf: &mut Buf, values: VLS)
where
    VLS: std::iter::IntoIterator<Item = &'c (OBJNM, VL)>,
    VLS::IntoIter: DoubleEndedIterator,
    OBJNM: crate::AsOidRaw + 'c,
    VL: std::borrow::Borrow<Value<'b>> + 'c,
{
    buf.push_sequence(|buf| {
        for itm in values.into_iter().rev() {
            buf.push_sequence(|buf| {
                match itm.1.borrow() {
                    Value::Boolean(b) => buf.push_boolean(*b),
                    Value::Null => buf.push_null(),
                    Value::Integer(i) => buf.push_integer(*i),
                    Value::OctetString(ostr) => buf.push_octet_string(ostr),
                    Value::ObjectIdentifier(ref objid) => {
                        buf.push_object_identifier_raw(objid.raw());
                    }
                    Value::IpAddress(ref ip) => buf.push_ipaddress(ip),
                    Value::Counter32(i) => buf.push_counter32(*i),
                    Value::Unsigned32(i) => buf.push_unsigned32(*i),
                    Value::Timeticks(tt) => buf.push_timeticks(*tt),
                    Value::Opaque(bytes) => buf.push_opaque(bytes),
                    Value::Counter64(i) => buf.push_counter64(*i),
                    Value::EndOfMibView => buf.push_endofmibview(),
                    Value::NoSuchObject => buf.push_nosuchobject(),
                    Value::NoSuchInstance => buf.push_nosuchinstance(),
                    _ => return,
                }
                buf.push_object_identifier_raw(itm.0.as_oid_raw());
            });
        }
    });
}
#[inline]
pub(crate) fn build_inner_raw<'c, 'b: 'c, VLS, OBJNM, VL>(
    req_id: i32,
    ident: u8,
    values: VLS,
    u1: u32, //non_repeaters|error_index
    u2: u32, //max_repetitions|error_status
    buf: &mut Buf,
) where
    VLS: std::iter::IntoIterator<Item = &'c (OBJNM, VL)>,
    VLS::IntoIter: DoubleEndedIterator,
    OBJNM: crate::AsOidRaw + 'c,
    VL: std::borrow::Borrow<Value<'b>> + 'c,
{
    buf.push_constructed(ident, |buf| {
        push_varbinds_raw(buf, values);
        buf.push_integer(u1.into());
        buf.push_integer(u2.into());
        buf.push_integer(i64::from(req_id));
    });
}
pub fn push_varbinds_oid<VLS, ITM>(buf: &mut Buf, values: VLS)
where
    VLS: std::iter::IntoIterator<Item = ITM>,
    VLS::IntoIter: DoubleEndedIterator,
    ITM: VarbindOid,
{
    buf.push_sequence(|buf| {
        for itm in values.into_iter().rev() {
            buf.push_sequence(|buf| {
                if let Some(v) = itm.value() {
                    match v {
                        Value::Boolean(b) => buf.push_boolean(*b),
                        Value::Null => buf.push_null(),
                        Value::Integer(i) => buf.push_integer(*i),
                        Value::OctetString(ostr) => buf.push_octet_string(ostr),
                        Value::ObjectIdentifier(ref objid) => {
                            buf.push_object_identifier_raw(objid.raw());
                        }
                        Value::IpAddress(ref ip) => buf.push_ipaddress(ip),
                        Value::Counter32(i) => buf.push_counter32(*i),
                        Value::Unsigned32(i) => buf.push_unsigned32(*i),
                        Value::Timeticks(tt) => buf.push_timeticks(*tt),
                        Value::Opaque(bytes) => buf.push_opaque(bytes),
                        Value::Counter64(i) => buf.push_counter64(*i),
                        Value::EndOfMibView => buf.push_endofmibview(),
                        Value::NoSuchObject => buf.push_nosuchobject(),
                        Value::NoSuchInstance => buf.push_nosuchinstance(),
                        _ => return,
                    }
                } else {
                    buf.push_null();
                }
                //buf.push_object_identifier_raw(itm.0.as_oid_raw());
                buf.push_object_identifier(itm.oid());
            });
        }
    });
}
#[inline]
pub fn build_inner_oid<VLS, ITM>(
    req_id: i32,
    ident: u8,
    values: VLS,
    u1: u32, //non_repeaters|error_index
    u2: u32, //max_repetitions|error_status
    buf: &mut Buf,
) where
    VLS: std::iter::IntoIterator<Item = ITM>,
    VLS::IntoIter: DoubleEndedIterator,
    ITM: VarbindOid,
{
    buf.push_constructed(ident, |buf| {
        push_varbinds_oid(buf, values);
        buf.push_integer(u1.into());
        buf.push_integer(u2.into());
        buf.push_integer(i64::from(req_id));
    });
}

pub fn build_v2<VLS, ITM>(
    ident: u8,
    community: &[u8],
    req_id: i32,
    values: VLS,
    u1: u32,
    u2: u32,
    buf: &mut Buf,
    version: i32,
) -> SnmpResult<()>
where
    VLS: std::iter::IntoIterator<Item = ITM>,
    VLS::IntoIter: DoubleEndedIterator,
    ITM: VarbindOid,
{
    buf.reset();
    buf.push_sequence(|buf| {
        buf.push_constructed(ident, |buf| {
            push_varbinds_oid(buf, values);
            buf.push_integer(u2 as i64); // error index
            buf.push_integer(u1 as i64); // error status
            buf.push_integer(req_id as i64);
        });
        buf.push_octet_string(community);
        push_version(buf, version);
    });
    Ok(())
}
pub fn build<VLS, ITM>(
    ident: u8,
    security: &SnmpSecurity,
    req_id: i32,
    values: VLS,
    u1: u32,
    u2: u32,
    buf: &mut Buf,
) -> SnmpResult<()>
where
    VLS: std::iter::IntoIterator<Item = ITM>,
    VLS::IntoIter: DoubleEndedIterator,
    ITM: VarbindOid,
{
    match security.credentials {
        SnmpCredentials::V12 {
            ref version,
            ref community,
        } => build_v2(
            ident,
            community,
            req_id,
            values,
            u1,
            u2,
            buf,
            *version as i32,
        ),
        #[cfg(feature = "v3")]
        SnmpCredentials::V3(ref sec) => {
            crate::v3::build_v3(ident, req_id, values, u1, u2, buf, sec, &security.state)
        }
    }
}
pub fn build_get<ITM>(
    security: &SnmpSecurity,
    req_id: i32,
    name: ITM,
    buf: &mut Buf,
) -> SnmpResult<()>
where
    ITM: VarbindOid,
{
    build(snmp::MSG_GET, security, req_id, [name], 0, 0, buf)
}
pub fn build_getmulti<NAMES, ITM>(
    security: &SnmpSecurity,
    req_id: i32,
    names: NAMES,
    buf: &mut Buf,
) -> SnmpResult<()>
where
    NAMES: std::iter::IntoIterator<Item = ITM>,
    NAMES::IntoIter: DoubleEndedIterator,
    ITM: VarbindOid,
{
    build(snmp::MSG_GET, security, req_id, names, 0, 0, buf)
}
fn push_version(buf: &mut Buf, version: i32) {
    match version {
        1 => buf.push_integer(snmp::VERSION_1 as i64),
        2 => buf.push_integer(snmp::VERSION_2 as i64),
        3 => buf.push_integer(snmp::VERSION_3 as i64),
        _ => buf.push_integer(snmp::VERSION_1 as i64),
    }
}
pub fn build_getnext<ITM>(
    security: &SnmpSecurity,
    req_id: i32,
    name: ITM,
    buf: &mut Buf,
) -> SnmpResult<()>
where
    ITM: VarbindOid,
{
    build(snmp::MSG_GET_NEXT, security, req_id, [name], 0, 0, buf)
}

pub fn build_getbulk<NAMES, ITM>(
    security: &SnmpSecurity,
    req_id: i32,
    names: NAMES,
    non_repeaters: u32,
    max_repetitions: u32,
    buf: &mut Buf,
) -> SnmpResult<()>
where
    NAMES: std::iter::IntoIterator<Item = ITM>,
    NAMES::IntoIter: DoubleEndedIterator,
    ITM: VarbindOid,
{
    build(
        snmp::MSG_GET_BULK,
        security,
        req_id,
        names,
        non_repeaters,
        max_repetitions,
        buf,
    )
}

pub fn build_set<NAMES, ITM>(
    security: &SnmpSecurity,
    req_id: i32,
    values: NAMES,
    buf: &mut Buf,
) -> SnmpResult<()>
where
    NAMES: std::iter::IntoIterator<Item = ITM>,
    NAMES::IntoIter: DoubleEndedIterator,
    ITM: VarbindOid,
{
    build(snmp::MSG_SET, security, req_id, values, 0, 0, buf)
}

pub fn build_response<NAMES, ITM>(
    security: &SnmpSecurity,
    req_id: i32,
    values: NAMES,
    buf: &mut Buf,
) -> SnmpResult<()>
where
    NAMES: std::iter::IntoIterator<Item = ITM>,
    NAMES::IntoIter: DoubleEndedIterator,
    ITM: crate::VarbindOid,
{
    build(snmp::MSG_RESPONSE, security, req_id, values, 0, 0, buf)
}
