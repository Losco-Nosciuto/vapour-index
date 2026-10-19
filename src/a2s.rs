//! A2S: the query protocol every Source server answers, and what DayZ hides inside it.
//!
//! Two questions get asked of each server. `A2S_INFO` says who it is right now — name, map, slots,
//! players, and the `bots` count that Valve's master list cannot be trusted for. `A2S_RULES` carries
//! the DayZ payload with the server's mod list, which is the only place mods are published.
//!
//! Why this matters more than it sounds: a farm copies a real community's name and slot count, so the
//! master list cannot tell them apart. What a farm cannot fake is *answering as itself*. Beans'
//! definition of a farm is "a dozen servers sharing an address, the same mod list, the same slot count,
//! the same name prefix, all nearly full" — three of those five signals only exist here.
//!
//! The DayZ payload format was read from the Beans launcher's published codec (source-available; the
//! format itself comes from `a2s-java-lib`). The implementation below is ours; the field order is
//! theirs to have documented.
//!
//! Deliberately small: UDP, no dependencies, and a reassembler that refuses anything implausible
//! rather than trusting a length field from a stranger.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

/// From the protocol: a split reply is at most 16 packets, and no honest reply is near this large.
const MAX_SPLIT_PACKETS: usize = 16;
const MAX_REASSEMBLED_BYTES: usize = 128 * 1024;
const MAX_DATAGRAM: usize = 4096;

const HEADER_SINGLE: i32 = -1; // 0xFFFFFFFF
const HEADER_SPLIT: i32 = -2; // 0xFFFFFFFE
const TYPE_INFO: u8 = 0x49; // 'I'
const TYPE_RULES: u8 = 0x45; // 'E'
const TYPE_CHALLENGE: u8 = 0x41; // 'A'

/// What a server says about itself.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Info {
    pub name: String,
    pub map: String,
    /// `dayz` for DayZ.
    pub folder: String,
    pub game: String,
    /// The protocol's id field is 16 bits wide, so DayZ's 221100 arrives as 24524. Useless for
    /// identifying the game — `folder` is the field that answers that.
    pub app_id_low: u16,
    pub players: u8,
    pub max_players: u8,
    /// DayZ has no bots. A non-zero value here is a server that has been modified — the one honest
    /// fabrication signal in the whole protocol, and the reason this field is worth the query.
    pub bots: u8,
    pub server_type: String,
    pub environment: String,
    pub visibility: u8,
    pub vac: u8,
    pub version: String,
}

/// One mod as the server advertises it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mod {
    /// Steam Workshop id, or 0 for a mod that is not published there.
    pub workshop_id: u64,
    pub name: String,
}

/// The DayZ payload inside `A2S_RULES`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DayzPayload {
    pub protocol_version: u8,
    /// False when the server flagged an overflow: its own list did not fit and is cut short.
    pub complete: bool,
    pub mods: Vec<Mod>,
    /// Key names the server accepts (`VPP`, `cftoolsRoot`…), which are not mods.
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Rules {
    /// The ordinary text rules, capped at 64 so a hostile server cannot make us grow.
    pub rules: BTreeMap<String, String>,
    /// Present only when the server published the DayZ payload.
    pub dayz: Option<DayzPayload>,
}

/// A raw result for one address, in the shape the artifact publishes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reading {
    pub addr: String,
    /// True when the server answered at all.
    pub answered: bool,
    /// Populated when it answered with A2S_INFO.
    pub info: Option<Info>,
    /// Populated when it answered with A2S_RULES and a DayZ payload could be decoded.
    pub mods: Option<DayzPayload>,
    /// Why it was not readable, when it was not.
    pub error: Option<String>,
}

impl Reading {
    /// A reachable server with no fabricated players and a slot count the engine can honour.
    ///
    /// Two facts, not opinions: DayZ has no bots, and DayZ caps at 127 slots. Beans blocks on the
    /// same two, from the same query.
    pub fn is_plausible(&self) -> bool {
        let Some(info) = &self.info else {
            return false;
        };
        info.bots == 0 && info.max_players <= 127
    }
}

/// What the servers themselves said, collected into something the filter can consult.
#[derive(Debug, Default)]
pub struct Verdicts {
    /// When the readings were published, for deciding whether they can be trusted at all.
    pub at: u64,
    /// Per address: bots claimed, whether it answered, and how many players it had.
    readings: std::collections::HashMap<String, (u8, bool, u8)>,
}

/// Readings older than this are treated as no reading. A stale verdict must never cost a server.
const VERDICT_LIFETIME_SECONDS: u64 = 60 * 60;

impl Verdicts {
    pub fn from_readings(readings: &[Reading], at: u64) -> Self {
        let mut by_addr = std::collections::HashMap::with_capacity(readings.len());
        for reading in readings {
            let bots = reading.info.as_ref().map(|info| info.bots).unwrap_or(0);
            let players = reading.info.as_ref().map(|info| info.players).unwrap_or(0);
            by_addr.insert(reading.addr.clone(), (bots, reading.answered, players));
        }
        Self { at, readings: by_addr }
    }

    /// Whether this is recent enough to act on.
    pub fn fresh(&self, now: u64) -> bool {
        now.saturating_sub(self.at) <= VERDICT_LIFETIME_SECONDS
    }

    pub fn get(&self, addr: &str) -> Option<(u8, bool, u8)> {
        self.readings.get(addr).copied()
    }

    pub fn len(&self) -> usize {
        self.readings.len()
    }
}

/// The address of a DayZ listing (`ip:queryport`) as a socket address.
fn socket_addr(addr: &str) -> Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs;
    addr.to_socket_addrs()
        .map_err(|e| format!("{addr}: {e}"))?
        .next()
        .ok_or_else(|| format!("{addr}: resolved to nothing"))
}

/// Builds an `A2S_INFO` request, optionally answering a challenge.
fn info_request(challenge: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x54];
    out.extend_from_slice(b"Source Engine Query\0");
    if let Some(c) = challenge {
        out.extend_from_slice(&c);
    }
    out
}

/// Builds an `A2S_RULES` request, optionally answering a challenge.
fn rules_request(challenge: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x56];
    match challenge {
        Some(c) => out.extend_from_slice(&c),
        None => out.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]),
    }
    out
}

/// Reassembles split replies, refusing anything that looks wrong rather than trusting it.
#[derive(Debug, Default)]
pub struct Assembler {
    id: i32,
    parts: Vec<Option<Vec<u8>>>,
    received: usize,
    bytes: usize,
}

impl Assembler {
    /// Feeds one datagram. `Ok(Some(body))` once a whole reply is in hand, where `body[0]` is the
    /// reply type and the rest is its payload.
    pub fn push(&mut self, datagram: &[u8]) -> Result<Option<Vec<u8>>, String> {
        if datagram.len() < 5 {
            return Err("shorter than an A2S header".to_string());
        }
        let header = i32::from_le_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);

        if header == HEADER_SINGLE {
            return Ok(Some(datagram[4..].to_vec()));
        }
        if header != HEADER_SPLIT {
            return Err(format!("not an A2S reply (header {header})"));
        }
        if datagram.len() < 12 {
            return Err("split header truncated".to_string());
        }

        let id = i32::from_le_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]);
        if id & 0x8000_0000u32 as i32 != 0 {
            return Err("compressed replies are not supported".to_string());
        }
        if self.id != id {
            // A different reply, or a retry after a timeout: start cleanly rather than mixing them.
            *self = Self::default();
            self.id = id;
        }

        let total = datagram[8] as usize;
        let number = datagram[9] as usize;
        if total == 0 || total > MAX_SPLIT_PACKETS {
            return Err(format!("split packet count out of range ({total})"));
        }
        if number >= total {
            return Err(format!("split packet index {number} of {total}"));
        }
        if self.parts.is_empty() {
            self.parts = vec![None; total];
        } else if self.parts.len() != total {
            return Err("split packets disagree on how many there are".to_string());
        }

        if self.parts[number].is_none() {
            let chunk = &datagram[12..];
            self.bytes += chunk.len();
            if self.bytes > MAX_REASSEMBLED_BYTES {
                return Err("reply larger than any honest one".to_string());
            }
            self.parts[number] = Some(chunk.to_vec());
            self.received += 1;
        }

        if self.received < self.parts.len() {
            return Ok(None);
        }

        let mut body = Vec::with_capacity(self.bytes);
        for part in &self.parts {
            let Some(chunk) = part else {
                return Ok(None);
            };
            body.extend_from_slice(chunk);
        }
        Ok(Some(body))
    }
}

/// A cursor over a reply body, where every read is bounds-checked.
struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    fn is_empty(&self) -> bool {
        self.at >= self.data.len()
    }

    fn u8(&mut self) -> Result<u8, String> {
        let v = *self.data.get(self.at).ok_or("reply truncated")?;
        self.at += 1;
        Ok(v)
    }

    fn u16(&mut self) -> Result<u16, String> {
        let a = self.u8()?;
        let b = self.u8()?;
        Ok(u16::from_le_bytes([a, b]))
    }

    fn skip(&mut self, n: usize) -> Result<(), String> {
        if self.at + n > self.data.len() {
            return Err("reply truncated".to_string());
        }
        self.at += n;
        Ok(())
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.at + n > self.data.len() {
            return Err("reply truncated".to_string());
        }
        let slice = &self.data[self.at..self.at + n];
        self.at += n;
        Ok(slice)
    }

    /// A NUL-terminated string, stopping at the end of the buffer rather than erroring: an old
    /// server with no version string is not a failure.
    fn cbytes(&mut self) -> Result<Vec<u8>, String> {
        let start = self.at;
        while self.at < self.data.len() && self.data[self.at] != 0 {
            self.at += 1;
        }
        if self.at >= self.data.len() {
            return Err("unterminated string".to_string());
        }
        let out = self.data[start..self.at].to_vec();
        self.at += 1;
        Ok(out)
    }

    fn cstring(&mut self) -> Result<String, String> {
        Ok(decode_text(&self.cbytes()?))
    }
}

fn decode_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .chars()
        .take(96)
        .collect()
}

/// Decodes an `A2S_INFO` reply body, including its type byte.
pub fn parse_info(body: &[u8]) -> Result<Info, String> {
    if body.first() != Some(&TYPE_INFO) {
        return Err(format!("not an info reply (type {:?})", body.first()));
    }
    let mut r = Reader::new(&body[1..]);
    let _protocol = r.u8()?;
    let name = r.cstring()?;
    let map = r.cstring()?;
    let folder = r.cstring()?;
    let game = r.cstring()?;
    let app_id_low = r.u16()?;
    let players = r.u8()?;
    let max_players = r.u8()?;
    let bots = r.u8()?;
    let server_type = r.u8()? as char;
    let environment = r.u8()? as char;
    let visibility = r.u8()?;
    let vac = r.u8()?;
    // Servers older than version reporting simply end here.
    let version = r.cstring().unwrap_or_default();

    Ok(Info {
        name,
        map,
        folder,
        game,
        app_id_low,
        players,
        max_players,
        bots,
        server_type: server_type.to_string(),
        environment: environment.to_string(),
        visibility,
        vac,
        version,
    })
}

/// Decodes an `A2S_RULES` reply body, including its type byte.
pub fn parse_rules(body: &[u8]) -> Result<Rules, String> {
    if body.first() != Some(&TYPE_RULES) {
        return Err(format!("not a rules reply (type {:?})", body.first()));
    }
    let mut r = Reader::new(&body[1..]);
    let count = r.u16()?;

    let mut rules = BTreeMap::new();
    let mut chunks: Vec<(u16, Vec<u8>)> = Vec::new();

    for _ in 0..count {
        if r.is_empty() {
            break;
        }
        let key = r.cbytes()?;
        let value = r.cbytes()?;
        if key.len() == 2 {
            // DayZ escapes zero bytes out of its payload, so both bytes of a two-character key are
            // non-zero — which makes a two-byte key the payload chunk's index, and no text rule is two
            // characters long. The index is escaped like everything else, so it must be undone before
            // it means anything: index 0 arrives as the bytes `01 02`.
            let index_bytes = unescape(&key);
            let index = index_bytes.iter().enumerate().fold(0u16, |acc, (place, byte)| {
                acc | (u16::from(*byte) << (8 * place as u16))
            });
            chunks.push((index, value));
        } else if rules.len() < 64 {
            rules.insert(decode_text(&key), decode_text(&value));
        }
    }

    let dayz = if chunks.is_empty() {
        None
    } else {
        Some(decode_dayz(&chunks)?)
    };

    Ok(Rules { rules, dayz })
}

/// Undoes the DayZ payload's escaping: `01 01` is a literal `01`, `01 02` is `00`, `01 03` is `FF`.
///
/// Any other `01 x` is passed through untouched, so a payload that uses `01` for something else stays
/// readable rather than shifting every field after it.
pub fn unescape(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x01 && i + 1 < bytes.len() {
            match bytes[i + 1] {
                0x01 => {
                    out.push(0x01);
                    i += 2;
                    continue;
                }
                0x02 => {
                    out.push(0x00);
                    i += 2;
                    continue;
                }
                0x03 => {
                    out.push(0xFF);
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Decodes the DayZ payload from the rule chunks.
///
/// Field order, after the chunks are sorted by index and concatenated and the escaping is undone:
/// protocol version, overflow flag, DLC flags (each set bit meaning four bytes of hash follow), mod
/// count, then per mod a four-byte hash, an id-length nibble, the little-endian Workshop id and a
/// name — and finally the signatures.
pub fn decode_dayz(chunks: &[(u16, Vec<u8>)]) -> Result<DayzPayload, String> {
    let mut sorted: Vec<&(u16, Vec<u8>)> = chunks.iter().collect();
    sorted.sort_by_key(|(key, _)| *key);

    let mut joined = Vec::new();
    for (_, value) in sorted {
        joined.extend_from_slice(value);
    }
    let bytes = unescape(&joined);

    let mut r = Reader::new(&bytes);
    let protocol_version = r.u8()?;
    let overflow = r.u8()?;
    let dlc_flags = r.u16()?;
    r.skip(4 * dlc_flags.count_ones() as usize)?;

    let count = r.u8()?;
    let mut mods = Vec::with_capacity(count as usize);
    for _ in 0..count {
        r.skip(4)?; // the mod's hash
        let id_length = (r.u8()? & 0x0f) as usize;
        if id_length > 8 {
            return Err(format!("workshop id of {id_length} bytes"));
        }
        let id_bytes = r.bytes(id_length)?;
        // Little-endian, as written by the server.
        let mut workshop_id = 0u64;
        for byte in id_bytes.iter().rev() {
            workshop_id = workshop_id * 256 + u64::from(*byte);
        }
        let name_length = r.u8()? as usize;
        let name = decode_text(r.bytes(name_length)?);
        mods.push(Mod { workshop_id, name });
    }

    // Signatures are best-effort: a server that truncates them has already told us its mod list.
    let mut signatures = Vec::new();
    let signature_count = r.u8().unwrap_or(0);
    for _ in 0..signature_count {
        let Ok(length) = r.u8() else { break };
        let Ok(raw) = r.bytes(length as usize) else { break };
        signatures.push(decode_text(raw));
    }

    Ok(DayzPayload {
        protocol_version,
        complete: overflow == 0,
        mods,
        signatures,
    })
}

/// A minimal A2S client: one UDP socket per query, one challenge round, then a decode.
pub struct Client {
    timeout: Duration,
}

impl Client {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Sends one request and collects a whole reply.
    async fn ask(&self, addr: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
        let target = socket_addr(addr)?;
        let bind = if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };

        let socket = UdpSocket::bind(bind).await.map_err(|e| format!("{addr}: bind: {e}"))?;
        socket.connect(target).await.map_err(|e| format!("{addr}: connect: {e}"))?;
        socket.send(payload).await.map_err(|e| format!("{addr}: send: {e}"))?;

        let mut assembler = Assembler::default();
        loop {
            let mut buffer = [0u8; MAX_DATAGRAM];
            let read = match tokio::time::timeout(self.timeout, socket.recv(&mut buffer)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(format!("{addr}: recv: {e}")),
                Err(_) => return Err(format!("{addr}: no reply in {:?}", self.timeout)),
            };
            if let Some(body) = assembler.push(&buffer[..read])? {
                return Ok(body);
            }
        }
    }

    /// Asks a server about itself.
    pub async fn info(&self, addr: &str) -> Result<Info, String> {
        let mut challenge = None;
        // Servers answer the first request with a challenge, and a rare one asks twice.
        for _ in 0..3 {
            let body = self.ask(addr, &info_request(challenge)).await?;
            match body.first().copied() {
                Some(TYPE_INFO) => return parse_info(&body),
                Some(TYPE_CHALLENGE) if body.len() >= 5 => {
                    challenge = Some([body[1], body[2], body[3], body[4]]);
                }
                other => return Err(format!("{addr}: unexpected info reply {other:?}")),
            }
        }
        Err(format!("{addr}: kept asking for a challenge"))
    }

    /// Asks a server for its rules, including the DayZ payload when it publishes one.
    pub async fn rules(&self, addr: &str) -> Result<Rules, String> {
        let mut challenge = None;
        for _ in 0..3 {
            let body = self.ask(addr, &rules_request(challenge)).await?;
            match body.first().copied() {
                Some(TYPE_RULES) => return parse_rules(&body),
                Some(TYPE_CHALLENGE) if body.len() >= 5 => {
                    challenge = Some([body[1], body[2], body[3], body[4]]);
                }
                other => return Err(format!("{addr}: unexpected rules reply {other:?}")),
            }
        }
        Err(format!("{addr}: kept asking for a challenge"))
    }

    /// Everything worth having from one server, in one reading.
    pub async fn read(&self, addr: &str) -> Reading {
        match self.info(addr).await {
            Ok(info) => {
                let mods = match self.rules(addr).await {
                    Ok(rules) => rules.dayz,
                    Err(_) => None,
                };
                Reading {
                    addr: addr.to_string(),
                    answered: true,
                    info: Some(info),
                    mods,
                    error: None,
                }
            }
            Err(error) => Reading {
                addr: addr.to_string(),
                answered: false,
                info: None,
                mods: None,
                error: Some(error),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datagram(parts: &[u8]) -> Vec<u8> {
        parts.to_vec()
    }

    #[test]
    fn a_single_reply_yields_its_body() {
        let mut a = Assembler::default();
        let body = a.push(&datagram(&[0xFF, 0xFF, 0xFF, 0xFF, 0x49, 0x11, 0x22])).unwrap();
        assert_eq!(body, Some(vec![0x49, 0x11, 0x22]), "the type byte stays with the body");
    }

    #[test]
    fn a_split_reply_is_put_back_in_order() {
        let mut a = Assembler::default();
        let id: i32 = 0x1234;
        let packet = |total: u8, number: u8, chunk: &[u8]| {
            let mut d = vec![0xFE, 0xFF, 0xFF, 0xFF];
            d.extend_from_slice(&id.to_le_bytes());
            d.push(total);
            d.push(number);
            d.extend_from_slice(&1248u16.to_le_bytes());
            d.extend_from_slice(chunk);
            d
        };

        // Fed out of order, on purpose.
        assert_eq!(a.push(&packet(3, 2, b"THREE")).unwrap(), None);
        assert_eq!(a.push(&packet(3, 0, b"ONE")).unwrap(), None);
        let done = a.push(&packet(3, 1, b"TWO")).unwrap().unwrap();
        assert_eq!(done, b"ONETWOTHREE".to_vec());
    }

    #[test]
    fn a_repeated_packet_does_not_duplicate_bytes() {
        let mut a = Assembler::default();
        let packet = |total: u8, number: u8, chunk: &[u8]| {
            let mut d = vec![0xFE, 0xFF, 0xFF, 0xFF];
            d.extend_from_slice(&7i32.to_le_bytes());
            d.push(total);
            d.push(number);
            d.extend_from_slice(&1248u16.to_le_bytes());
            d.extend_from_slice(chunk);
            d
        };
        a.push(&packet(2, 0, b"AA")).unwrap();
        a.push(&packet(2, 0, b"AA")).unwrap();
        let done = a.push(&packet(2, 1, b"BB")).unwrap().unwrap();
        assert_eq!(done, b"AABB".to_vec());
    }

    #[test]
    fn implausible_replies_are_refused_not_trusted() {
        let mut a = Assembler::default();
        let id: i32 = 1;
        let head = |total: u8, number: u8| {
            let mut d = vec![0xFE, 0xFF, 0xFF, 0xFF];
            d.extend_from_slice(&id.to_le_bytes());
            d.push(total);
            d.push(number);
            d.extend_from_slice(&1248u16.to_le_bytes());
            d
        };
        assert!(a.push(&head(0, 0)).is_err(), "zero packets");
        assert!(a.push(&head(99, 0)).is_err(), "more packets than the protocol allows");
        assert!(a.push(&head(2, 5)).is_err(), "packet number beyond the count");

        // Compressed replies (high bit set) are refused rather than misread.
        let mut compressed = vec![0xFE, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x80];
        compressed.extend_from_slice(&[1, 0, 0, 0]);
        assert!(Assembler::default().push(&compressed).is_err());
    }

    #[test]
    fn dayz_escapes_are_undone() {
        assert_eq!(unescape(&[0x01, 0x01]), vec![0x01]);
        assert_eq!(unescape(&[0x01, 0x02]), vec![0x00]);
        assert_eq!(unescape(&[0x01, 0x03]), vec![0xFF]);
        // An 01 followed by anything else is left alone rather than eating the next byte.
        assert_eq!(unescape(&[0x01, 0x07]), vec![0x01, 0x07]);
        assert_eq!(unescape(&[0x05, 0x01]), vec![0x05, 0x01]);
    }

    /// The escaping a server applies before putting binary into a value that must stay NUL-free: a raw
    /// zero would end the cstring, which is the whole reason this escaping exists.
    fn escape(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len());
        for byte in bytes {
            match byte {
                0x01 => out.extend_from_slice(&[0x01, 0x01]),
                0x00 => out.extend_from_slice(&[0x01, 0x02]),
                0xFF => out.extend_from_slice(&[0x01, 0x03]),
                other => out.push(*other),
            }
        }
        out
    }

    /// Builds a DayZ payload the way a server does, so the decoder is tested against the format
    /// rather than against itself.
    fn dayz_payload(protocol: u8, overflow: u8, mods: &[(u64, &str)], signatures: &[&str]) -> Vec<u8> {
        let mut out = vec![protocol, overflow, 0x00, 0x00]; // no DLC flags, so no hashes
        out.push(mods.len() as u8);
        for (id, name) in mods {
            out.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // hash, four bytes
            let id_bytes = id.to_le_bytes();
            let used = id_bytes.iter().rposition(|b| *b != 0).map(|i| i + 1).unwrap_or(0);
            out.push(used as u8); // the low nibble is the id length
            out.extend_from_slice(&id_bytes[..used]);
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
        }
        out.push(signatures.len() as u8);
        for signature in signatures {
            out.push(signature.len() as u8);
            out.extend_from_slice(signature.as_bytes());
        }
        // Escaped last, exactly as a server does it before the bytes go into rule values.
        escape(&out)
    }

    /// Splits a payload into rule chunks the way a server does: two-byte escaped keys, values as the
    /// escaped payload bytes.
    fn as_chunks(payload: &[u8]) -> Vec<(u16, Vec<u8>)> {
        payload
            .chunks(1200)
            .enumerate()
            .map(|(i, chunk)| (i as u16, chunk.to_vec()))
            .collect()
    }

    /// The key bytes a server would send for a chunk index: escaped, so index 0 becomes `01 02`.
    fn chunk_key(index: u16) -> Vec<u8> {
        escape(&[index as u8])
    }

    #[test]
    fn a_mod_list_decodes_with_ids_and_names() {
        let payload = dayz_payload(
            1,
            0,
            &[(1559212036, "CF"), (2545327648, "A very long mod name"), (0, "Local only")],
            &["VPP", "cftoolsRoot"],
        );
        let dayz = decode_dayz(&as_chunks(&payload)).expect("a well-formed payload decodes");

        assert_eq!(dayz.protocol_version, 1);
        assert!(dayz.complete, "overflow 0 means the server sent its whole list");
        assert_eq!(dayz.mods.len(), 3);
        assert_eq!(dayz.mods[0].workshop_id, 1559212036);
        assert_eq!(dayz.mods[0].name, "CF");
        assert_eq!(dayz.mods[1].workshop_id, 2545327648, "ids are little-endian");
        assert_eq!(dayz.mods[1].name, "A very long mod name");
        assert_eq!(dayz.mods[2].workshop_id, 0, "a mod with no Workshop id");
        assert_eq!(dayz.signatures, vec!["VPP".to_string(), "cftoolsRoot".to_string()]);
    }

    #[test]
    fn an_overflow_flag_marks_the_list_incomplete() {
        let payload = dayz_payload(1, 1, &[(1, "Only the first")], &[]);
        let dayz = decode_dayz(&as_chunks(&payload)).unwrap();
        assert!(!dayz.complete, "the server said its list did not fit");
        assert_eq!(dayz.mods.len(), 1);
    }

    #[test]
    fn a_chunked_payload_survives_being_split_across_packets() {
        // Enough mods to span several chunks. The unescaped form is what is split, because that is
        // what a server escapes before the bytes go into rule values.
        let mods: Vec<(u64, &str)> = (0..40).map(|i| (1000 + i, "Mod")).collect();
        let mut raw = dayz_payload(1, 0, &mods, &[]);
        raw.truncate(raw.len());

        let dayz = decode_dayz(&as_chunks(&raw)).expect("splitting must not corrupt the payload");
        assert_eq!(dayz.mods.len(), 40);
        assert_eq!(dayz.mods[39].workshop_id, 1039);
    }

    #[test]
    fn text_rules_and_payload_chunks_are_told_apart() {
        // A reply shaped like a real one: ordinary text rules plus the DayZ chunks.
        let dayz = dayz_payload(1, 0, &[(1559212036, "CF")], &[]);
        let entries: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b"version".to_vec(), b"1.27".to_vec()),
            (b"mods".to_vec(), b"1".to_vec()),
            (chunk_key(0), dayz.clone()),
            (chunk_key(1), b"second chunk".to_vec()),
        ];

        let mut body = vec![TYPE_RULES];
        body.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        for (key, value) in &entries {
            body.extend_from_slice(key);
            body.push(0);
            body.extend_from_slice(value);
            body.push(0);
        }

        let rules = parse_rules(&body).expect("a rules reply parses");
        assert_eq!(rules.rules.get("version").map(String::as_str), Some("1.27"));
        assert_eq!(rules.rules.get("mods").map(String::as_str), Some("1"));
        let decoded = rules.dayz.expect("the DayZ payload is found");
        assert_eq!(decoded.mods.len(), 1);
        assert_eq!(decoded.mods[0].name, "CF");
    }

    #[test]
    fn an_info_reply_parses_including_bots() {
        let mut body = vec![TYPE_INFO, 17];
        for text in ["[TAG] A Server", "chernarusplus", "dayz", "DayZ"] {
            body.extend_from_slice(text.as_bytes());
            body.push(0);
        }
        body.extend_from_slice(&24524u16.to_le_bytes()); // 221100 as the protocol's 16-bit field
        body.push(12); // players
        body.push(60); // max players
        let bots_at = body.len();
        body.push(0); // bots
        body.extend_from_slice(&[b'd', b'w', 0, 1]); // type, environment, visibility, vac
        body.extend_from_slice(b"1.27\0");

        let info = parse_info(&body).unwrap();
        assert_eq!(info.name, "[TAG] A Server");
        assert_eq!(info.folder, "dayz");
        // 221100 truncated to the protocol's 16-bit field.
        assert_eq!(info.app_id_low, 24524);
        assert_eq!(info.players, 12);
        assert_eq!(info.max_players, 60);
        assert_eq!(info.bots, 0);
        assert_eq!(info.version, "1.27");

        // And the fabrication signal: bots, which DayZ never has.
        let mut liar = body.clone();
        liar[bots_at] = 40;
        assert_eq!(parse_info(&liar).unwrap().bots, 40);
    }

    /// Hits real servers through the relay's published list. Slower than the unit tests and the only
    /// way to know the wire format is right: `cargo test -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "network test against live DayZ servers"]
    async fn live_servers_answer() {
        let client = Client::new(Duration::from_secs(3));
        for addr in ["185.83.152.173:2303", "31.77.142.124:42359"] {
            match client.read(addr).await {
                reading if reading.answered => {
                    let info = reading.info.as_ref().unwrap();
                    println!(
                        "{addr}  {}  {}/{}  bots {}  map {}  mods {:?}",
                        info.name,
                        info.players,
                        info.max_players,
                        info.bots,
                        info.map,
                        reading.mods.as_ref().map(|m| m.mods.len()),
                    );
                    assert!(info.folder.eq_ignore_ascii_case("dayz") || info.game.contains("DayZ"));
                }
                reading => println!("{addr}  no answer: {:?}", reading.error),
            }
        }
    }
}
