//! STAR archives (DASL `star.html`, @atproto/star): a metadata header,
//! then key/value pairs each after a `0x01` control byte, then a `0x00`.
//!
//! ```text
//! [ magic | len | meta ] [ 1 | len | key | len | val ] ... [ 0 ]
//! ```
//!
//! Each `len` is an unsigned varint in its shortest form; the metadata is a
//! canonical DRISL map with a string `$type` naming the profile. Space
//! repos (`atproto-space-repo`: getRepo, importRepo) and space meta
//! (`atproto-space-meta`: exportSpaceMeta, importSpaceMeta) are the two
//! profiles here, both capping the metadata at 64 KiB, a key at 4 KiB and a
//! value at 1 MiB.
//!
//! [`Reader`] parses incrementally from whatever is buffered, so a body is
//! read as it arrives and a frame over its limit is refused from its
//! length, before it's buffered.

use vlatproto::cbor::Value;

pub const MAGIC: [u8; 4] = [0x2a, 0x6c, 0x01, 0x00];
const CONTROL_PAIR: u8 = 0x01;
const CONTROL_END: u8 = 0x00;
const MAX_VARINT_BYTES: usize = 9;

pub const REPO_TYPE: &str = "atproto-space-repo";
pub const META_TYPE: &str = "atproto-space-meta";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub meta: usize,
    pub key: usize,
    pub value: usize,
}

/// Both profiles' limits (`REPO_STAR_LIMITS`, `SPACE_META_STAR_LIMITS`).
pub const LIMITS: Limits = Limits { meta: 64 << 10, key: 4 << 10, value: 1 << 20 };

/// No limits, as generic STAR sets none.
pub const UNLIMITED: Limits = Limits { meta: usize::MAX, key: usize::MAX, value: usize::MAX };

/// The reference's `StarParseError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarError(pub String);

impl std::fmt::Display for StarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn err<T>(m: impl Into<String>) -> Result<T, StarError> {
    Err(StarError(m.into()))
}

pub fn write_varint(out: &mut Vec<u8>, mut n: u64) {
    while n >= 0x80 {
        out.push((n as u8 & 0x7f) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

/// The magic and the metadata (its DRISL bytes).
pub fn write_header(out: &mut Vec<u8>, meta: &[u8]) {
    out.extend_from_slice(&MAGIC);
    write_varint(out, meta.len() as u64);
    out.extend_from_slice(meta);
}

pub fn write_pair(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    out.push(CONTROL_PAIR);
    write_varint(out, key.len() as u64);
    out.extend_from_slice(key);
    write_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

pub fn write_end(out: &mut Vec<u8>) {
    out.push(CONTROL_END);
}

/// What [`Reader::step`] found at the front of the buffer.
#[derive(Debug, PartialEq)]
pub enum Item {
    /// The metadata map, checked canonical.
    Meta(Value),
    Pair { key: Vec<u8>, value: Vec<u8> },
    /// The end byte, and nothing after it (checked at EOF).
    End,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Magic,
    Control,
    Ended,
}

/// An incremental reader: hand [`Reader::step`] the unread bytes.
pub struct Reader {
    limits: Limits,
    stage: Stage,
}

/// A varint at the front of `buf`: Ok(None) when more bytes are needed.
fn read_varint(buf: &[u8], eof: bool) -> Result<Option<(u64, usize)>, StarError> {
    let mut v = 0u64;
    for i in 0..MAX_VARINT_BYTES {
        let Some(&b) = buf.get(i) else {
            return if eof { err("unexpected end of archive") } else { Ok(None) };
        };
        v |= ((b & 0x7f) as u64) << (7 * i);
        if b < 0x80 {
            // a final zero byte only pads the encoding
            if b == 0 && i > 0 {
                return err("non-canonical varint");
            }
            return Ok(Some((v, i + 1)));
        }
    }
    err("varint too long")
}

/// A frame at the front of `buf`: (start, end) of its bytes and the bytes
/// consumed, Ok(None) when more are needed.
fn read_frame(buf: &[u8], eof: bool, max: usize) -> Result<Option<(usize, usize)>, StarError> {
    let Some((len, n)) = read_varint(buf, eof)? else { return Ok(None) };
    if len > max as u64 {
        return err(format!("length {len} exceeds limit of {max}"));
    }
    let end = n + len as usize;
    if buf.len() < end {
        return if eof { err("unexpected end of archive") } else { Ok(None) };
    }
    Ok(Some((n, end)))
}

fn parse_meta(bytes: &[u8]) -> Result<Value, StarError> {
    let meta = Value::decode(bytes).map_err(|_| StarError("invalid metadata".into()))?;
    match &meta {
        Value::Map(m) if m.iter().any(|(k, v)| k == "$type" && matches!(v, Value::Text(_))) => {}
        _ => return err("metadata must be a map with a $type"),
    }
    let mut again = Vec::with_capacity(bytes.len());
    meta.encode(&mut again);
    if again != bytes {
        return err("metadata is not canonical DRISL");
    }
    Ok(meta)
}

impl Reader {
    pub fn new(limits: Limits) -> Reader {
        Reader { limits, stage: Stage::Magic }
    }

    /// The next item in `buf` (the unread bytes) and how many bytes it
    /// took; Ok(None) when more bytes are needed. `eof`: `buf` is all that's
    /// left. After [`Item::End`], call again with `eof` to check nothing
    /// follows (Ok(None) then means a clean end).
    pub fn step(&mut self, buf: &[u8], eof: bool) -> Result<Option<(Item, usize)>, StarError> {
        match self.stage {
            Stage::Magic => {
                if buf.len() < MAGIC.len() {
                    return if eof { err("invalid magic bytes") } else { Ok(None) };
                }
                if buf[..MAGIC.len()] != MAGIC {
                    return err("invalid magic bytes");
                }
                let Some((s, e)) = read_frame(&buf[MAGIC.len()..], eof, self.limits.meta)? else { return Ok(None) };
                let meta = parse_meta(&buf[MAGIC.len() + s..MAGIC.len() + e])?;
                self.stage = Stage::Control;
                Ok(Some((Item::Meta(meta), MAGIC.len() + e)))
            }
            Stage::Control => {
                let Some(&control) = buf.first() else {
                    return if eof { err("unexpected end of archive") } else { Ok(None) };
                };
                match control {
                    CONTROL_END => {
                        self.stage = Stage::Ended;
                        Ok(Some((Item::End, 1)))
                    }
                    CONTROL_PAIR => {
                        let rest = &buf[1..];
                        let Some((ks, ke)) = read_frame(rest, eof, self.limits.key)? else { return Ok(None) };
                        let Some((vs, ve)) = read_frame(&rest[ke..], eof, self.limits.value)? else {
                            return Ok(None);
                        };
                        let item = Item::Pair { key: rest[ks..ke].to_vec(), value: rest[ke + vs..ke + ve].to_vec() };
                        Ok(Some((item, 1 + ke + ve)))
                    }
                    c => err(format!("invalid control byte: {c}")),
                }
            }
            Stage::Ended if buf.is_empty() => Ok(None),
            Stage::Ended => err("unexpected bytes after end of archive"),
        }
    }
}

/// A whole archive in memory: its metadata and pairs.
pub fn read_all(mut buf: &[u8], limits: Limits) -> Result<(Value, Vec<(Vec<u8>, Vec<u8>)>), StarError> {
    let mut r = Reader::new(limits);
    let (mut meta, mut pairs) = (None, Vec::new());
    loop {
        match r.step(buf, true)? {
            Some((Item::Meta(m), n)) => {
                meta = Some(m);
                buf = &buf[n..];
            }
            Some((Item::Pair { key, value }, n)) => {
                pairs.push((key, value));
                buf = &buf[n..];
            }
            Some((Item::End, n)) => {
                buf = &buf[n..];
                r.step(buf, true)?;
                return Ok((meta.expect("the metadata comes first"), pairs));
            }
            None => unreachable!("eof answers or fails"),
        }
    }
}

/// A space repo commit as STAR metadata: the commit plus `$type`, in
/// canonical key order.
pub fn repo_meta(c: &super::commit::Commit) -> Vec<u8> {
    use vlatproto::cbor;
    let mut b = Vec::with_capacity(160 + c.space.len() + c.repo.len());
    cbor::write_map_head(&mut b, 6);
    cbor::write_text(&mut b, "rev");
    cbor::write_text(&mut b, &c.rev);
    cbor::write_text(&mut b, "ver");
    cbor::write_int(&mut b, c.ver);
    cbor::write_text(&mut b, "data");
    cbor::write_bytes(&mut b, &c.data);
    cbor::write_text(&mut b, "repo");
    cbor::write_text(&mut b, &c.repo);
    cbor::write_text(&mut b, "$type");
    cbor::write_text(&mut b, REPO_TYPE);
    cbor::write_text(&mut b, "space");
    cbor::write_text(&mut b, &c.space);
    b
}

/// The reference's `repoStarMeta` check: the repo profile's metadata.
pub fn parse_repo_meta(meta: &Value) -> Result<super::commit::Commit, StarError> {
    let Value::Map(m) = meta else { return err("invalid repo metadata") };
    let get = |k: &str| m.iter().find(|(key, _)| key == k).map(|(_, v)| v);
    if get("$type") != Some(&Value::Text(REPO_TYPE.into())) {
        return err("invalid repo metadata: $type must be atproto-space-repo");
    }
    let text = |k: &str| match get(k) {
        Some(Value::Text(s)) => Ok(s.clone()),
        _ => err(format!("invalid repo metadata: {k}")),
    };
    let ver = match get("ver") {
        Some(Value::Int(v)) => *v,
        _ => return err("invalid repo metadata: ver"),
    };
    let data = match get("data") {
        Some(Value::Bytes(b)) => b.clone(),
        _ => return err("invalid repo metadata: data"),
    };
    let repo = text("repo")?;
    if !vlatproto::syntax::valid_did(&repo) {
        return err("invalid repo metadata: repo");
    }
    let space = text("space")?;
    if vlatproto::syntax::parse_space_uri(&space).is_none_or(|s| s.record.is_some()) {
        return err("invalid repo metadata: space");
    }
    if ver != super::commit::COMMIT_VERSION {
        return err(format!("unsupported commit version: {ver}"));
    }
    let data: [u8; 32] = data.try_into().map_err(|_| StarError("invalid repo metadata: data".into()))?;
    Ok(super::commit::Commit { ver, repo, space, rev: text("rev")?, data })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::vectors::VECTORS;

    fn fixtures(name: &str) -> serde_json::Value {
        let path = format!("{}/testdata/spaces-alpha/star-interop/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn hex_of(v: &serde_json::Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }

    /// The DASL interop fixtures (testdata/spaces-alpha/star-interop),
    /// whole and fed one byte at a time.
    #[test]
    fn interop_fixtures() {
        for f in fixtures("valid-star-fixtures.json").as_array().unwrap() {
            let bytes = hex_of(&f["star_hex"]);
            let (_, pairs) = read_all(&bytes, UNLIMITED).unwrap_or_else(|e| panic!("{}: {e}", f["comment"]));
            let want: Vec<(Vec<u8>, Vec<u8>)> = f["decoded"]["pairs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| (hex_of(&p["key_hex"]), hex_of(&p["value_hex"])))
                .collect();
            assert_eq!(pairs, want, "{}", f["comment"]);
            assert_eq!(trickle(&bytes).unwrap().1, want, "{}", f["comment"]);
        }
        for f in fixtures("invalid-star-fixtures.json").as_array().unwrap() {
            let bytes = hex_of(&f["star_hex"]);
            assert!(read_all(&bytes, UNLIMITED).is_err(), "{}", f["comment"]);
            assert!(trickle(&bytes).is_err(), "{}", f["comment"]);
        }
    }

    /// Reads `bytes` handing the reader one more byte each time it asks.
    fn trickle(bytes: &[u8]) -> Result<(Value, Vec<(Vec<u8>, Vec<u8>)>), StarError> {
        let mut r = Reader::new(UNLIMITED);
        let (mut pos, mut have) = (0, 0);
        let (mut meta, mut pairs) = (None, Vec::new());
        loop {
            let eof = have == bytes.len();
            match r.step(&bytes[pos..have], eof)? {
                None if eof => return Ok((meta.ok_or(StarError("no end".into()))?, pairs)),
                None => have += 1,
                Some((item, n)) => {
                    pos += n;
                    match item {
                        Item::Meta(m) => meta = Some(m),
                        Item::Pair { key, value } => pairs.push((key, value)),
                        Item::End => {}
                    }
                }
            }
        }
    }

    /// testdata/spaces-alpha/vectors.json `star`: archives the reference
    /// wrote (serializeRepo, serializeSpaceMeta).
    #[test]
    fn generated_vectors() {
        for s in VECTORS["star"].as_array().unwrap() {
            let bytes = hex_of(&s["star"]);
            let (meta, pairs) = read_all(&bytes, LIMITS).unwrap();
            if s["profile"] != REPO_TYPE {
                continue;
            }
            let ctx = &s["ctx"];
            let c = parse_repo_meta(&meta).unwrap();
            assert_eq!((c.space.as_str(), c.repo.as_str(), c.rev.as_str()), (
                ctx["space"].as_str().unwrap(),
                ctx["repo"].as_str().unwrap(),
                ctx["rev"].as_str().unwrap()
            ));
            assert_eq!(hex::encode(c.data), s["data"].as_str().unwrap());
            // and writing the same commit and records gives the same bytes
            let mut out = Vec::new();
            write_header(&mut out, &repo_meta(&c));
            let records = s["records"].as_array().unwrap();
            assert_eq!(records.len(), pairs.len());
            for r in records {
                write_pair(&mut out, r["path"].as_str().unwrap().as_bytes(), &hex_of(&r["bytes"]));
            }
            write_end(&mut out);
            assert_eq!(out, bytes);
        }
    }

    #[test]
    fn limits_and_framing() {
        let c = crate::space::commit::Commit {
            ver: 1,
            repo: "did:plc:x".into(),
            space: "at://did:plc:x/space/com.example.group/self".into(),
            rev: "3kbcq3p7ad401".into(),
            data: [0; 32],
        };
        let mut out = Vec::new();
        write_header(&mut out, &repo_meta(&c));
        write_pair(&mut out, b"a.b.c/1", &vec![0; LIMITS.value + 1]);
        write_end(&mut out);
        assert!(read_all(&out, LIMITS).unwrap_err().0.contains("exceeds limit"));
        // refused from the length, before the value arrives
        let mut r = Reader::new(LIMITS);
        let (_, n) = r.step(&out, false).unwrap().unwrap();
        assert!(r.step(&out[n..n + 16], false).unwrap_err().0.contains("exceeds limit"));
        // truncated: no end byte
        let mut t = Vec::new();
        write_header(&mut t, &repo_meta(&c));
        write_pair(&mut t, b"a.b.c/1", b"\xa0");
        assert!(read_all(&t, LIMITS).unwrap_err().0.contains("unexpected end"));
        // an unknown commit version
        let mut m = repo_meta(&crate::space::commit::Commit { ver: 2, ..c.clone() });
        let (meta, _) = {
            let mut b = Vec::new();
            write_header(&mut b, &m);
            write_end(&mut b);
            read_all(&b, LIMITS).unwrap()
        };
        assert_eq!(parse_repo_meta(&meta).unwrap_err().0, "unsupported commit version: 2");
        m.clear();
        // a varint
        for n in [0u64, 127, 128, 300, 1 << 40] {
            let mut v = Vec::new();
            write_varint(&mut v, n);
            assert_eq!(read_varint(&v, true).unwrap(), Some((n, v.len())));
        }
    }
}
