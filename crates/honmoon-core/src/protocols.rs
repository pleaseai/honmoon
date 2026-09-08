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

/// The verb reported when a statement has no classifiable leading word — it is
/// empty, or starts with punctuation rather than a keyword. A rule can name it
/// (`sql.verb == 'UNKNOWN'`) and deny it; echoing the punctuation back as the
/// verb instead would put an attacker-chosen string into the facts, where it can
/// only ever fail to match every rule.
pub const UNKNOWN_VERB: &str = "UNKNOWN";

/// Parse the leading verb and best-effort table out of a SQL statement.
///
/// Heuristic, not a full SQL grammar — enough to drive policy on the dangerous
/// verbs (`DROP`, `TRUNCATE`, `DELETE`, `UPDATE`, `INSERT`, `SELECT`). A verb it
/// does not recognize is reported as-is and carries no table; recognizing a verb
/// is not a precondition for allowing a statement, so ordinary traffic (`WITH`,
/// `EXPLAIN`, `SET`, `BEGIN`, …) is unaffected. An unclassifiable statement gets
/// [`UNKNOWN_VERB`].
pub fn parse_sql(query: &str) -> SqlFacts {
    // A comment prologue must not be able to hide the verb: PostgreSQL skips
    // `/* audit */` and `-- x` and executes what follows, so honmoon has to look
    // past them too — otherwise `/* audit */ DROP TABLE users` parses as the verb
    // `/*` and no `sql.verb == 'DROP'` rule ever sees it.
    let query = strip_leading_comments(query);
    let mut tokens = query.split_whitespace();
    let verb = match tokens.next() {
        // A keyword starts with a letter or `_`; anything else is not a verb we
        // can classify, and must not be echoed back into the facts.
        Some(token) if token.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') => {
            token.to_ascii_uppercase()
        }
        _ => UNKNOWN_VERB.to_owned(),
    };

    // Table extraction depends on the verb's syntax.
    let table = match verb.as_str() {
        // DROP TABLE [IF EXISTS] x / TRUNCATE [TABLE] [ONLY] x / DROP MATERIALIZED VIEW x
        "DROP" | "TRUNCATE" => {
            // Skip leading object-type and option keywords; the first token that
            // is not one of these is the relation name.
            const MODIFIERS: &[&str] = &[
                "table",
                "view",
                "materialized",
                "index",
                "sequence",
                "schema",
                "database",
                "if",
                "exists",
                "concurrently",
                "only",
            ];
            tokens
                .find(|t| !MODIFIERS.iter().any(|m| t.eq_ignore_ascii_case(m)))
                .unwrap_or_default()
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

/// Whether a SQL statement string carries more than one statement.
///
/// The `Q` (simple query) message may legally batch statements, but [`parse_sql`]
/// only ever classifies the first verb, so `SELECT 1; DROP TABLE users` would be
/// decided as a `SELECT`. The data plane refuses a batch rather than forward one
/// uninspected, which makes this deliberately conservative: it errs toward
/// "multiple" on anything it cannot follow. It must still not trip over an
/// ordinary statement, so semicolons inside string literals, quoted identifiers,
/// dollar-quoted bodies and comments are not separators, and a single trailing
/// `;` is still one statement.
pub fn carries_multiple_statements(query: &str) -> bool {
    let bytes = query.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if let Some((end, terminated)) = comment_end(bytes, i) {
            if !terminated {
                return true; // unterminated comment: the rest is unreadable
            }
            i = end;
            continue;
        }
        match bytes[i] {
            // A string literal or a quoted identifier, where the quote is
            // doubled to escape itself.
            quote @ (b'\'' | b'"') => {
                i += 1;
                loop {
                    match bytes.get(i) {
                        // Unterminated: honmoon cannot tell where the statement
                        // ends, so it is not inspectable.
                        None => return true,
                        Some(&c) if c == quote => {
                            if bytes.get(i + 1) == Some(&quote) {
                                i += 2;
                            } else {
                                i += 1;
                                break;
                            }
                        }
                        Some(_) => i += 1,
                    }
                }
            }
            // A `$` only opens a dollar quote at a token boundary: PostgreSQL
            // allows `$` inside an identifier after its first character, so the
            // `$tag$` in `foo$tag$` is part of the name, not an opener. Reading
            // it as one would let `SELECT foo$tag$; DROP TABLE users$tag$` hide
            // its separator inside a string that is not there.
            b'$' if !starts_identifier_continuation(bytes, i) => match dollar_tag_end(bytes, i) {
                Some(body) => {
                    let tag = &bytes[i..body];
                    match bytes[body..].windows(tag.len()).position(|w| w == tag) {
                        Some(end) => i = body + end + tag.len(),
                        None => return true, // unterminated dollar quote
                    }
                }
                // `$1` and friends are parameter placeholders, not quotes.
                None => i += 1,
            },
            b';' => {
                // A trailing separator is still one statement, and so is one
                // followed only by whitespace or a comment.
                let mut j = i + 1;
                loop {
                    while bytes.get(j).is_some_and(u8::is_ascii_whitespace) {
                        j += 1;
                    }
                    match comment_end(bytes, j) {
                        // An unterminated comment hides whatever follows it.
                        Some((_, false)) => return true,
                        Some((end, true)) => j = end,
                        None => return j < bytes.len(),
                    }
                }
            }
            _ => i += 1,
        }
    }
    false
}

/// Skip leading whitespace and comments, so the caller sees the first real token.
fn strip_leading_comments(query: &str) -> &str {
    let bytes = query.as_bytes();
    let mut i = 0;
    loop {
        while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        match comment_end(bytes, i) {
            Some((end, _)) => i = end,
            None => return query.get(i..).unwrap_or_default(),
        }
    }
}

/// If a SQL comment opens at `start`, where it ends.
///
/// `Some((end, terminated))`: `end` is the index just past the comment (the end
/// of the input when it never closed) and `terminated` says whether it closed —
/// callers weigh that differently, since reading a verb is simply over at the
/// end of the input while a scanner looking for statement separators cannot
/// trust what it never saw. `None` when no comment opens at `start`. A `--`
/// comment runs to the end of its line; `/* */` blocks **nest**, as PostgreSQL's do.
fn comment_end(bytes: &[u8], start: usize) -> Option<(usize, bool)> {
    match (bytes.get(start)?, bytes.get(start + 1)) {
        (b'-', Some(b'-')) => Some(match bytes[start..].iter().position(|b| *b == b'\n') {
            Some(end) => (start + end + 1, true),
            None => (bytes.len(), true),
        }),
        (b'/', Some(b'*')) => {
            let mut depth = 1usize;
            let mut i = start + 2;
            while depth > 0 {
                match (bytes.get(i), bytes.get(i + 1)) {
                    (Some(b'/'), Some(b'*')) => {
                        depth += 1;
                        i += 2;
                    }
                    (Some(b'*'), Some(b'/')) => {
                        depth -= 1;
                        i += 2;
                    }
                    (Some(_), _) => i += 1,
                    (None, _) => return Some((bytes.len(), false)),
                }
            }
            Some((i, true))
        }
        _ => None,
    }
}

/// Whether the byte before `start` is an identifier character, i.e. whatever is
/// at `start` continues a name rather than starting a new token.
fn starts_identifier_continuation(bytes: &[u8], start: usize) -> bool {
    start
        .checked_sub(1)
        .and_then(|prev| bytes.get(prev))
        .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'$')
}

/// If a `$` at `start` opens a dollar quote (`$$` or `$tag$`), the index just
/// past its opening delimiter; `None` when it is something else.
fn dollar_tag_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    while let Some(&c) = bytes.get(i) {
        match c {
            b'$' => return Some(i + 1),
            // A tag is an identifier, and it may not start with a digit — that
            // is a positional parameter.
            b'_' | b'a'..=b'z' | b'A'..=b'Z' => i += 1,
            b'0'..=b'9' if i > start + 1 => i += 1,
            _ => return None,
        }
    }
    None
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

    if rest.first() == Some(&"namespaces") && rest.len() >= 3 {
        // Namespaced resource: namespaces/{ns}/{resource}/{name?}
        namespace = rest[1].to_ascii_lowercase();
        resource = rest[2].to_ascii_lowercase();
        has_resource_name = rest.len() >= 4;
    } else if rest.first() == Some(&"namespaces") {
        // The Namespace resource itself: `/api/v1/namespaces` (list) or
        // `/api/v1/namespaces/{name}` (get) — `namespaces` IS the resource.
        resource = "namespaces".to_string();
        has_resource_name = rest.len() == 2;
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
    fn drop_if_exists_extracts_real_table() {
        assert_eq!(parse_sql("DROP TABLE IF EXISTS users").table, "users");
        assert_eq!(parse_sql("DROP MATERIALIZED VIEW mv").table, "mv");
        assert_eq!(parse_sql("TRUNCATE ONLY accounts").table, "accounts");
        assert_eq!(parse_sql("DROP INDEX CONCURRENTLY idx_a").table, "idx_a");
    }

    #[test]
    fn k8s_namespace_resource_itself() {
        // Regression: `namespaces` as the cluster-scoped resource, not a prefix.
        let list = parse_k8s_request("GET", "/api/v1/namespaces");
        assert_eq!(list.resource, "namespaces");
        assert_eq!(list.namespace, "");
        assert_eq!(list.verb, "list");

        let get = parse_k8s_request("DELETE", "/api/v1/namespaces/prod");
        assert_eq!(get.resource, "namespaces");
        assert_eq!(get.namespace, "");
        assert_eq!(get.verb, "delete"); // named → delete a namespace

        // Still parses a namespaced resource under a namespace.
        let secret = parse_k8s_request("GET", "/api/v1/namespaces/prod/secrets");
        assert_eq!(secret.resource, "secrets");
        assert_eq!(secret.namespace, "prod");
    }

    #[test]
    fn a_comment_prologue_cannot_hide_the_verb() {
        // PostgreSQL skips the comment and executes the DROP, so honmoon must
        // classify it as a DROP too — otherwise the prefix is a one-line bypass.
        let block = parse_sql("/* audit */ DROP TABLE users");
        assert_eq!(block.verb, "DROP");
        assert_eq!(block.table, "users");

        let line = parse_sql("-- audit\nDROP TABLE users");
        assert_eq!(line.verb, "DROP");
        assert_eq!(line.table, "users");

        // Nested and stacked comments, and a plain statement, are unaffected.
        assert_eq!(
            parse_sql("/* a /* b */ c */ /* d */ TRUNCATE t").verb,
            "TRUNCATE"
        );
        assert_eq!(parse_sql("SELECT * FROM orders").verb, "SELECT");
    }

    #[test]
    fn an_unclassifiable_statement_reports_the_unknown_verb() {
        // Nothing but a comment, and punctuation where a keyword belongs: the
        // facts must carry a verb a rule can deny, not attacker-chosen text.
        assert_eq!(parse_sql("").verb, UNKNOWN_VERB);
        assert_eq!(parse_sql("/* nothing else */").verb, UNKNOWN_VERB);
        assert_eq!(parse_sql(";;").verb, UNKNOWN_VERB);
        // An unrecognized *keyword* is still reported as itself — an unknown
        // verb is not a refusal, and ordinary sessions use plenty of them.
        assert_eq!(parse_sql("VACUUM FULL orders").verb, "VACUUM");
        assert_eq!(
            parse_sql("with x as (select 1) select * from x").verb,
            "WITH"
        );
    }

    #[test]
    fn detects_a_second_statement_in_a_simple_query() {
        assert!(carries_multiple_statements("SELECT 1; DROP TABLE users"));
        assert!(carries_multiple_statements(
            "SELECT 1;\n  DROP TABLE users;"
        ));
    }

    #[test]
    fn a_single_statement_survives_its_trailing_semicolon() {
        assert!(!carries_multiple_statements("SELECT 1"));
        assert!(!carries_multiple_statements("SELECT 1;"));
        assert!(!carries_multiple_statements("SELECT 1;  \n"));
    }

    #[test]
    fn a_quoted_or_commented_semicolon_is_not_a_separator() {
        assert!(!carries_multiple_statements("SELECT ';' FROM orders"));
        assert!(!carries_multiple_statements(
            "SELECT 'it''s; fine' FROM orders"
        ));
        assert!(!carries_multiple_statements(
            r#"SELECT "we;ird" FROM orders"#
        ));
        assert!(!carries_multiple_statements(
            "SELECT $tag$a; b$tag$ FROM orders"
        ));
        assert!(!carries_multiple_statements("SELECT $$a;b$$"));
        assert!(!carries_multiple_statements(
            "SELECT 1 -- ; not a statement"
        ));
        assert!(!carries_multiple_statements("SELECT /* ; /* ; */ ; */ 1"));
        assert!(
            !carries_multiple_statements("SELECT * FROM t WHERE id = $1"),
            "`$1` is a parameter, not a dollar quote"
        );
    }

    #[test]
    fn a_dollar_inside_an_identifier_does_not_open_a_quote() {
        // `foo$tag$` is one identifier, so the `;` is a real separator — reading
        // the `$tag$` as a string opener would skip straight past it.
        assert!(carries_multiple_statements(
            "SELECT foo$tag$; DROP TABLE users$tag$"
        ));
        assert!(!carries_multiple_statements("SELECT a$b FROM orders"));
    }

    #[test]
    fn a_trailing_comment_after_the_separator_is_not_a_second_statement() {
        assert!(!carries_multiple_statements(
            "SELECT 1; -- trailing comment"
        ));
        assert!(!carries_multiple_statements("SELECT 1; /* trailing */"));
        assert!(!carries_multiple_statements("SELECT 1; /* a */ -- b\n  "));
        assert!(
            carries_multiple_statements("SELECT 1; /* unterminated"),
            "a comment that never closes could be hiding a statement"
        );
    }

    #[test]
    fn an_unterminated_quote_or_comment_errs_toward_refusing() {
        assert!(carries_multiple_statements("SELECT 'oops"));
        assert!(carries_multiple_statements("SELECT $tag$oops"));
        assert!(carries_multiple_statements("SELECT /* oops"));
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
