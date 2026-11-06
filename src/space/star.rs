//! STAR-lite v1 archives (@atproto/space `star.ts`), the `atproto-space-repo`
//! profile getRepo serves: a header, then key/value pairs until EOF.
//!
//! ```text
//! [ magic | len | meta ] [ len | path | len | record ] [ len | path | len | record ] ...
//! ```
//!
//! The magic is `2a 6c 01 00`, each `len` an unsigned varint in its
//! shortest form. The metadata is the repo's commit plus `"$type":
//! "atproto-space-repo"`, as canonical DRISL; each pair is a record path
//! (`{collection}/{rkey}`) and the record's DRISL bytes (at most 1 MiB), in
//! strict bytewise order of the paths. The MAC is in the response's
//! `Atproto-Space-Mac` header, not the archive.
//!
//! See <https://tangled.org/microcosm.blue/star/tree/main/v1-star>.

use super::commit::Commit;
use super::lthash::LtHash;

pub const MAGIC: [u8; 4] = [0x2a, 0x6c, 0x01, 0x00];
pub const REPO_STAR_TYPE: &str = "atproto-space-repo";
/// The largest record a space repo holds (the reference's `MAX_RECORD_SIZE`).
pub const MAX_RECORD_SIZE: usize = 1 << 20;
/// STAR's own frame limits; this profile's records are capped lower.
pub const MAX_META_LENGTH: u64 = 64 << 20;
pub const MAX_KEY_LENGTH: u64 = 64 << 20;
/// A varint longer than this is refused (the reference reads 6 bytes).
pub const MAX_VARINT_BYTES: usize = 6;

/// The reference's `StarParseError`, and the profile's checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarError(pub String);

impl std::fmt::Display for StarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn fail(m: impl Into<String>) -> StarError {
    StarError(m.into())
}

pub fn write_varint(out: &mut Vec<u8>, n: u64) {
    vlatproto::car::write_varint(out, n)
}

/// The archive's start: the magic and the commit as its metadata.
pub fn write_header(out: &mut Vec<u8>, commit: &Commit) {
    out.extend_from_slice(&MAGIC);
    let meta = commit.to_cbor(Some(REPO_STAR_TYPE));
    write_varint(out, meta.len() as u64);
    out.extend_from_slice(&meta);
}

/// One record's pair.
pub fn write_pair(out: &mut Vec<u8>, path: &[u8], record: &[u8]) {
    write_varint(out, path.len() as u64);
    out.extend_from_slice(path);
    write_varint(out, record.len() as u64);
    out.extend_from_slice(record);
}

/// A varint at the front of `b`: Ok(None) when `b` ends before it does.
/// Non-minimal encodings (a final zero byte after the first) and ones past
/// [`MAX_VARINT_BYTES`] are refused.
pub fn read_varint(b: &[u8]) -> Result<Option<(u64, usize)>, StarError> {
    let mut n = 0u64;
    for i in 0..MAX_VARINT_BYTES {
        let Some(&byte) = b.get(i) else { return Ok(None) };
        n |= ((byte & 0x7f) as u64) << (7 * i);
        if byte < 0x80 {
            if byte == 0 && i > 0 {
                return Err(fail("non-canonical varint"));
            }
            return Ok(Some((n, i + 1)));
        }
    }
    Err(fail("varint too long"))
}

/// The metadata as the commit it carries: a canonical DRISL map whose
/// `$type` is this profile's.
pub fn parse_meta(b: &[u8]) -> Result<Commit, StarError> {
    use vlatproto::cbor::ValueRef;
    let v = vlatproto::cbor::Value::decode(b).map_err(|e| fail(format!("invalid metadata: {e}")))?;
    if v.to_cbor() != b {
        return Err(fail("metadata is not canonical DRISL"));
    }
    let v = ValueRef::decode(b).map_err(|e| fail(format!("invalid metadata: {e}")))?;
    if !matches!(v, ValueRef::Map(_)) || !matches!(v.get("$type"), Some(ValueRef::Text(_))) {
        return Err(fail("metadata must be a map with a $type"));
    }
    if v.get("$type").and_then(|t| t.as_str()) != Some(REPO_STAR_TYPE) {
        return Err(fail(format!("invalid repo metadata: $type must be {REPO_STAR_TYPE}")));
    }
    let text = |k: &str| match v.get(k) {
        Some(ValueRef::Text(t)) => Ok(t.to_string()),
        _ => Err(fail(format!("invalid repo metadata: {k} must be a string"))),
    };
    let ver = match v.get("ver") {
        Some(ValueRef::Int(n)) => *n,
        _ => return Err(fail("invalid repo metadata: ver must be an integer")),
    };
    let data = match v.get("data") {
        Some(ValueRef::Bytes(b)) => b.to_vec(),
        _ => return Err(fail("invalid repo metadata: data must be bytes")),
    };
    let (repo, space) = (text("repo")?, text("space")?);
    if !vlatproto::syntax::valid_did(&repo) {
        return Err(fail("invalid repo metadata: repo must be a DID"));
    }
    if vlatproto::syntax::parse_space_uri(&space).is_none_or(|u| u.record.is_some()) {
        return Err(fail("invalid repo metadata: space must be a space URI"));
    }
    Ok(Commit { ver, repo, space, rev: text("rev")?, data })
}

/// What a whole archive in memory holds: its commit and its records as
/// (path, record bytes), checked as [`Archive::push`] checks them.
#[derive(Debug)]
pub struct Parsed {
    pub commit: Commit,
    pub records: Vec<(String, Vec<u8>)>,
}

/// A repo archive checked as it's read (the reference's `verifyRepoStar`
/// past the MAC): paths in strict order, each a record path, records
/// within [`MAX_RECORD_SIZE`] and DRISL maps, folded into a set hash that
/// must equal the commit's `data` at the end.
pub struct Archive {
    pub commit: Commit,
    pub set: LtHash,
    prev: Option<Vec<u8>>,
    pub records: u64,
}

impl Archive {
    pub fn new(commit: Commit) -> Archive {
        Archive { commit, set: LtHash::default(), prev: None, records: 0 }
    }

    /// The pair's path (`{collection}/{rkey}`, split) and record CID.
    pub fn push(&mut self, key: &[u8], value: &[u8]) -> Result<(String, vlatproto::cid::Cid), StarError> {
        let path = std::str::from_utf8(key).map_err(|_| fail("a record path isn't UTF-8"))?;
        if self.prev.as_deref().is_some_and(|p| key <= p) {
            return Err(fail(format!("records out of order at {path}")));
        }
        self.prev = Some(key.to_vec());
        let (collection, rkey) = path
            .split_once('/')
            .filter(|(c, r)| vlatproto::syntax::valid_nsid(c) && vlatproto::syntax::valid_rkey(r))
            .ok_or_else(|| fail(format!("invalid record path {path}")))?;
        if value.len() > MAX_RECORD_SIZE {
            return Err(fail(format!("record at {path} is over {MAX_RECORD_SIZE} bytes")));
        }
        match vlatproto::cbor::ValueRef::decode(value) {
            Ok(vlatproto::cbor::ValueRef::Map(_)) => {}
            Ok(_) => return Err(fail(format!("invalid record at {path}"))),
            Err(_) => return Err(fail(format!("invalid record cbor at {path}"))),
        }
        let cid = vlatproto::cid::Cid::dag_cbor(value);
        self.set.add(&super::commit::element(collection, rkey, &cid.to_string()));
        self.records += 1;
        Ok((path.to_string(), cid))
    }

    /// At EOF: the records are the repo the commit describes.
    pub fn finish(&self) -> Result<(), StarError> {
        match super::commit::matches(&self.set, &self.commit) {
            true => Ok(()),
            false => Err(fail("records do not match the commit data")),
        }
    }
}

/// A whole archive: the header, the pairs to EOF, the digest. Its commit's
/// MAC (and repo and space) are the caller's to check.
pub fn parse(b: &[u8]) -> Result<Parsed, StarError> {
    let rest = b.strip_prefix(&MAGIC[..]).ok_or_else(|| fail("invalid magic bytes"))?;
    let mut pos = 0;
    let mut frame = |max: u64, at_eof_ok: bool| -> Result<Option<&[u8]>, StarError> {
        if pos == rest.len() && at_eof_ok {
            return Ok(None);
        }
        let (len, n) = read_varint(&rest[pos..])?.ok_or_else(|| fail("unexpected end of archive"))?;
        if len > max {
            return Err(fail(format!("length {len} exceeds limit of {max}")));
        }
        let start = pos + n;
        let end = start
            .checked_add(len as usize)
            .filter(|e| *e <= rest.len())
            .ok_or_else(|| fail("unexpected end of archive"))?;
        pos = end;
        Ok(Some(&rest[start..end]))
    };
    let meta = frame(MAX_META_LENGTH, false)?.ok_or_else(|| fail("missing metadata"))?;
    let mut a = Archive::new(parse_meta(meta)?);
    let mut records = Vec::new();
    while let Some(key) = frame(MAX_KEY_LENGTH, true)? {
        let value = frame(MAX_RECORD_SIZE as u64, false)?.ok_or_else(|| fail("missing value for key"))?;
        let (path, _) = a.push(key, value)?;
        records.push((path, value.to_vec()));
    }
    a.finish()?;
    Ok(Parsed { commit: a.commit, records })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::vectors::VECTORS;

    fn rec(text: &str) -> Vec<u8> {
        vlatproto::cbor::Value::from_json(&serde_json::json!({"$type": "a.b.c", "text": text})).unwrap().to_cbor()
    }

    fn archive(commit: &Commit, records: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        write_header(&mut out, commit);
        for (p, r) in records {
            write_pair(&mut out, p.as_bytes(), r);
        }
        out
    }

    fn commit_over(records: &[(&str, Vec<u8>)]) -> Commit {
        let mut set = LtHash::default();
        for (p, r) in records {
            let (c, k) = p.split_once('/').unwrap();
            set.add(&crate::space::commit::element(c, k, &vlatproto::cid::Cid::dag_cbor(r).to_string()));
        }
        Commit::of(&set, "at://did:example:space/space/a.b.c/k", "did:example:alice", "3kbcq3p7ad400")
    }

    /// testdata/spaces-alpha/vectors.json `star`: archives the reference's
    /// `serializeRepo` wrote, byte for byte what this writes.
    #[test]
    fn generated_vectors() {
        let cases = VECTORS["star"].as_array().unwrap();
        assert!(!cases.is_empty());
        for c in cases {
            let bytes = hex::decode(c["archive"].as_str().unwrap()).unwrap();
            let p = parse(&bytes).unwrap();
            assert_eq!(p.commit, Commit::from_json(&c["commit"]).unwrap());
            let mut out = Vec::new();
            write_header(&mut out, &p.commit);
            for (path, r) in &p.records {
                write_pair(&mut out, path.as_bytes(), r);
            }
            assert_eq!(out, bytes);
            assert_eq!(p.records.len() as u64, c["records"].as_u64().unwrap());
        }
    }

    #[test]
    fn round_trip_and_refusals() {
        let records = vec![("a.b.c/1", rec("one")), ("a.b.c/2", rec("two")), ("a.b.d/1", rec("three"))];
        let commit = commit_over(&records);
        let b = archive(&commit, &records);
        let p = parse(&b).unwrap();
        assert_eq!(p.commit, commit);
        assert_eq!(p.records.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(), ["a.b.c/1", "a.b.c/2", "a.b.d/1"]);

        // an empty repo has no pairs
        let empty = commit_over(&[]);
        assert!(parse(&archive(&empty, &[])).unwrap().records.is_empty());

        // out of order, a duplicate
        let mut swapped = records.clone();
        swapped.swap(0, 1);
        assert!(parse(&archive(&commit, &swapped)).unwrap_err().0.contains("out of order"));
        let dup = vec![records[0].clone(), records[0].clone()];
        assert!(parse(&archive(&commit_over(&dup[..1]), &dup)).unwrap_err().0.contains("out of order"));
        // a record missing, or one too many
        assert!(parse(&archive(&commit, &records[..2])).unwrap_err().0.contains("commit data"));
        // truncated anywhere past the header
        for cut in 1..8 {
            assert!(parse(&b[..b.len() - cut]).is_err(), "{cut}");
        }
        // oversized
        let big = vlatproto::cbor::Value::from_json(&serde_json::json!({"t": "x".repeat(MAX_RECORD_SIZE)}))
            .unwrap()
            .to_cbor();
        let e = parse(&archive(&commit_over(&[("a.b.c/1", big.clone())]), &[("a.b.c/1", big)])).unwrap_err();
        assert!(e.0.contains("exceeds limit"), "{e}");
        // bad magic, a bad path, a record that isn't a map
        assert!(parse(&b[1..]).is_err());
        assert!(parse(&archive(&commit, &[("no-slash", rec("x"))])).unwrap_err().0.contains("record path"));
        let five = vlatproto::cbor::Value::Int(5).to_cbor();
        assert!(parse(&archive(&commit, &[("a.b.c/1", five)])).unwrap_err().0.contains("invalid record"));
        // the metadata's $type
        let mut other = Vec::new();
        other.extend_from_slice(&MAGIC);
        let meta = commit.to_cbor(Some("other"));
        write_varint(&mut other, meta.len() as u64);
        other.extend_from_slice(&meta);
        assert!(parse(&other).unwrap_err().0.contains("$type"));
        let mut none = Vec::new();
        none.extend_from_slice(&MAGIC);
        let meta = commit.to_cbor(None);
        write_varint(&mut none, meta.len() as u64);
        none.extend_from_slice(&meta);
        assert!(parse(&none).is_err());
    }

    #[test]
    fn varints() {
        assert_eq!(read_varint(&[0]), Ok(Some((0, 1))));
        assert_eq!(read_varint(&[0x80, 0x01]), Ok(Some((128, 2))));
        assert_eq!(read_varint(&[0x80]), Ok(None));
        assert!(read_varint(&[0x81, 0x00]).is_err(), "a padding zero");
        assert!(read_varint(&[0xff; 7]).is_err());
        let mut b = Vec::new();
        write_varint(&mut b, MAX_RECORD_SIZE as u64);
        assert_eq!(read_varint(&b), Ok(Some((MAX_RECORD_SIZE as u64, b.len()))));
    }
}
