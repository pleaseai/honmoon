//! Wire-level protocol parsers that extract [`Facts`](crate::Facts).
//!
//! These are pure functions over byte/string input so they can be unit-tested
//! without a network. The proxy/relay layer (`honmoon-proxy`) is responsible for
//! reading bytes off the wire and feeding them here.
//!
//! Scope: we extract only the declared facts (verb/table/resource/namespace),
//! never decrypt or buffer full payloads beyond what a rule needs.

use crate::{K8sFacts, SqlFacts};

/// Parse a PostgreSQL **simple query** message (`'Q'`) into [`SqlFacts`].
///
/// Wire format (frontend `Query`): `b'Q'` | `Int32 length` | `String` (the SQL
/// text, NUL-terminated). `length` counts itself + the string but not the tag.
/// Returns `None` if `packet` is not a well-formed `Q` message.
pub fn parse_postgres_query(packet: &[u8]) -> Option<SqlFacts> {
    if packet.first() != Some(&b'Q') || packet.len() < 5 {
        return None;
    }
    let len = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]) as usize;
    // `len` covers the 4 length bytes + the NUL-terminated query string, and the
    // frame must match the buffer exactly — reject trailing/short bytes. The
    // shortest valid body is a lone NUL, so `len >= 5`.
    if len < 5 || 1 + len != packet.len() {
        return None;
    }
    // Body is `packet[5..]` and MUST end in a single NUL terminator.
    let body = &packet[5..];
    if body.last() != Some(&0) {
        return None;
    }
    let query = std::str::from_utf8(&body[..body.len() - 1]).ok()?;
    Some(parse_sql(query))
}

/// Parse the leading verb and best-effort table out of a SQL statement.
///
/// Heuristic, not a full SQL grammar — enough to drive policy on the dangerous
/// verbs (`DROP`, `TRUNCATE`, `DELETE`, `UPDATE`, `INSERT`, `SELECT`).
pub fn parse_sql(query: &str) -> SqlFacts {
    let mut tokens = query.split_whitespace();
    let verb = tokens.next().unwrap_or_default().to_ascii_uppercase();

    // Table extraction depends on the verb's syntax.
    let table = match verb.as_str() {
        // DROP TABLE x / TRUNCATE TABLE x / TRUNCATE x
        "DROP" | "TRUNCATE" => {
            let mut rest = tokens;
            let next = rest.next().unwrap_or_default();
            // Skip an optional object keyword (TABLE/VIEW/INDEX/...).
            if next.eq_ignore_ascii_case("table")
                || next.eq_ignore_ascii_case("view")
                || next.eq_ignore_ascii_case("index")
            {
                rest.next().unwrap_or_default()
            } else {
                next
            }
        }
        // INSERT INTO x / DELETE FROM x / SELECT ... FROM x
        "INSERT" | "DELETE" | "SELECT" => {
            // Find the token after the first FROM/INTO keyword.
            let mut found = "";
            let mut prev_kw = false;
            for tok in query.split_whitespace().skip(1) {
                if prev_kw {
                    found = tok;
                    break;
                }
                if tok.eq_ignore_ascii_case("from") || tok.eq_ignore_ascii_case("into") {
                    prev_kw = true;
                }
            }
            found
        }
        // UPDATE x SET ...
        "UPDATE" => tokens.next().unwrap_or_default(),
        _ => "",
    };

    SqlFacts {
        verb,
        table: clean_identifier(table),
    }
}

/// Normalize a SQL identifier: strip quotes, a trailing `;`, schema qualifier,
/// and lowercase. `public.users;` → `users`.
fn clean_identifier(raw: &str) -> String {
    raw.trim_matches(|c| c == '"' || c == '`' || c == '\'' || c == ';')
        .rsplit('.')
        .next()
        .unwrap_or("")
        .trim_matches(|c| c == '"' || c == '`')
        .to_ascii_lowercase()
}

/// Derive [`K8sFacts`] from a Kubernetes API request (HTTP method + path).
///
/// Recognizes both core (`/api/v1/...`) and grouped (`/apis/{group}/{version}/...`)
/// API paths, with or without a `namespaces/{ns}` segment. The HTTP method maps to
/// the resource verb (`GET` → `list`/`get`, `POST` → `create`, etc.).
pub fn parse_k8s_request(method: &str, path: &str) -> K8sFacts {
    let segments: Vec<&str> = path
        .split('?')
        .next()
        .unwrap_or(path)
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    // Skip the fixed API prefix so the version segment is never mistaken for a
    // resource: core APIs are `/api/{version}/…` (2 segments), grouped APIs are
    // `/apis/{group}/{version}/…` (3 segments).
    let prefix = match segments.first() {
        Some(&"api") => 2,
        Some(&"apis") => 3,
        _ => 0,
    };
    let rest = segments.get(prefix..).unwrap_or(&[]);

    let mut namespace = String::new();
    let mut resource = String::new();
    let mut has_resource_name = false;

    if rest.first() == Some(&"namespaces") {
        // namespaces/{ns}/{resource}/{name?}
        if let Some(ns) = rest.get(1) {
            namespace = ns.to_ascii_lowercase();
        }
        if let Some(res) = rest.get(2) {
            resource = res.to_ascii_lowercase();
            has_resource_name = rest.len() >= 4;
        }
    } else if let Some(res) = rest.first() {
        // Cluster-scoped: {resource}/{name?}
        resource = res.to_ascii_lowercase();
        has_resource_name = rest.len() >= 2;
    }

    let verb = k8s_verb(method, has_resource_name);
    K8sFacts {
        verb,
        resource,
        namespace,
    }
}

/// Map an HTTP method to a Kubernetes verb. `GET` on a collection is `list`,
/// `GET` on a named resource is `get`.
fn k8s_verb(method: &str, has_resource_name: bool) -> String {
    match method.to_ascii_uppercase().as_str() {
        "GET" => {
            if has_resource_name {
                "get"
            } else {
                "list"
            }
        }
        "POST" => "create",
        "PUT" => "update",
        "PATCH" => "patch",
        "DELETE" => "delete",
        _ => "",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pg_query(sql: &str) -> Vec<u8> {
        // Build a frontend Query message: 'Q' | len(i32) | sql\0
        let body = format!("{sql}\0");
        let len = (4 + body.len()) as u32;
        let mut packet = vec![b'Q'];
        packet.extend_from_slice(&len.to_be_bytes());
        packet.extend_from_slice(body.as_bytes());
        packet
    }

    #[test]
    fn parses_postgres_drop() {
        let facts = parse_postgres_query(&pg_query("DROP TABLE users;")).unwrap();
        assert_eq!(facts.verb, "DROP");
        assert_eq!(facts.table, "users");
    }

    #[test]
    fn parses_postgres_truncate_and_select() {
        assert_eq!(
            parse_postgres_query(&pg_query("TRUNCATE accounts"))
                .unwrap()
                .verb,
            "TRUNCATE"
        );
        let sel =
            parse_postgres_query(&pg_query("SELECT * FROM public.orders WHERE id = 1")).unwrap();
        assert_eq!(sel.verb, "SELECT");
        assert_eq!(sel.table, "orders");
    }

    #[test]
    fn rejects_non_query_packet() {
        assert!(parse_postgres_query(b"X\0\0\0\x04").is_none());
        assert!(parse_postgres_query(b"Q").is_none());
    }

    #[test]
    fn rejects_malformed_query_frames() {
        // Trailing extra bytes beyond the declared frame length.
        let mut trailing = pg_query("SELECT 1");
        trailing.push(b'!');
        assert!(parse_postgres_query(&trailing).is_none());

        // Body not NUL-terminated: 'Q' | len=8 | "SELECT" (no NUL).
        let mut no_nul = vec![b'Q'];
        no_nul.extend_from_slice(&8u32.to_be_bytes());
        no_nul.extend_from_slice(b"SELECT");
        assert!(parse_postgres_query(&no_nul).is_none());

        // Length field larger than the buffer.
        let mut short = vec![b'Q'];
        short.extend_from_slice(&100u32.to_be_bytes());
        short.extend_from_slice(b"x\0");
        assert!(parse_postgres_query(&short).is_none());
    }

    #[test]
    fn k8s_grouped_cluster_scoped_resource_not_version() {
        // Regression: `v1` must not be captured as the resource.
        let f = parse_k8s_request("GET", "/apis/apps/v1/deployments/api");
        assert_eq!(f.resource, "deployments");
        assert_eq!(f.namespace, "");
        assert_eq!(f.verb, "get"); // named resource → get
    }

    #[test]
    fn parse_sql_extracts_verb_and_table() {
        assert_eq!(parse_sql("delete from \"Sessions\"").table, "sessions");
        assert_eq!(parse_sql("INSERT INTO logs (a) VALUES (1)").table, "logs");
        assert_eq!(parse_sql("update Users set x=1").table, "users");
        assert_eq!(parse_sql("EXPLAIN ANALYZE foo").verb, "EXPLAIN");
    }

    #[test]
    fn parses_k8s_namespaced_delete() {
        let f = parse_k8s_request("DELETE", "/api/v1/namespaces/prod/secrets/db-password");
        assert_eq!(f.verb, "delete");
        assert_eq!(f.resource, "secrets");
        assert_eq!(f.namespace, "prod");
    }

    #[test]
    fn parses_k8s_list_vs_get() {
        let list = parse_k8s_request("GET", "/api/v1/namespaces/default/pods");
        assert_eq!(list.verb, "list");
        assert_eq!(list.resource, "pods");

        let get = parse_k8s_request("GET", "/api/v1/namespaces/default/pods/web-0");
        assert_eq!(get.verb, "get");
    }

    #[test]
    fn parses_k8s_grouped_api_and_cluster_scoped() {
        let deploy = parse_k8s_request("PATCH", "/apis/apps/v1/namespaces/staging/deployments/api");
        assert_eq!(deploy.verb, "patch");
        assert_eq!(deploy.resource, "deployments");
        assert_eq!(deploy.namespace, "staging");

        let nodes = parse_k8s_request("GET", "/api/v1/nodes");
        assert_eq!(nodes.resource, "nodes");
        assert_eq!(nodes.namespace, "");
        assert_eq!(nodes.verb, "list");
    }
}
