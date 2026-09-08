//! Wire-level protocol parsers that extract [`Facts`](crate::Facts).
//!
//! These are pure functions over byte/string input so they can be unit-tested
//! without a network. The proxy/relay layer (`honmoon-proxy`) is responsible for
//! reading bytes off the wire and feeding them here.
//!
//! Scope: we extract only the declared facts (verb/table/resource/namespace),
//! never decrypt or buffer full payloads beyond what a rule needs.

use crate::{K8sFacts, SqlFacts};
use sqlparser::ast::{
    Expr, FromTable, ObjectName, Query, SetExpr, Statement, TableFactor, TableObject,
    UtilityOption, Value,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

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

/// The verbs a statement can *execute*, most dangerous first.
///
/// One statement may run more than one of them: `EXPLAIN ANALYZE` runs what it
/// wraps, and a data-modifying CTE runs inside an outer `SELECT`. Rules here are
/// deny-oriented (`sql.verb == 'DELETE'` refuses), so the fail-safe answer is
/// the most dangerous verb the statement actually executes — under-reporting
/// hands an attacker a bypass, while over-reporting can only refuse something.
/// The ordering lives here, once, rather than scattered across match arms.
///
/// `MERGE` outranks `DELETE`, `UPDATE` and `INSERT` because one `MERGE` can do
/// all three, so it must not be reported as the weaker of them.
const VERB_PRECEDENCE: &[&str] = &[
    "DROP", "TRUNCATE", "ALTER", "MERGE", "DELETE", "UPDATE", "INSERT", "SELECT",
];

/// Parse the leading verb and best-effort table out of a SQL statement.
///
/// Parses with PostgreSQL's own grammar (`sqlparser`) so honmoon agrees with the
/// server about what a statement *executes*, not merely what it starts with: an
/// `EXPLAIN ANALYZE DELETE …` is a `DELETE`, and so is a `SELECT` over a
/// data-modifying CTE. Where several verbs execute, the most dangerous one wins
/// ([`VERB_PRECEDENCE`]). Only the first statement is classified; a batch is
/// refused separately by [`carries_multiple_statements`].
///
/// Input the parser cannot read falls back to [`parse_sql_heuristic`], the
/// leading-token scanner that shipped before it — so unparseable-but-benign
/// traffic keeps classifying exactly as it does today, and no path through this
/// function is more permissive than that scanner alone.
pub fn parse_sql(query: &str) -> SqlFacts {
    let Ok(statements) = Parser::parse_sql(&PostgreSqlDialect {}, query) else {
        return parse_sql_heuristic(query);
    };
    let Some(statement) = statements.first() else {
        // Nothing to run at all (empty input, only comments, only separators).
        return SqlFacts {
            verb: UNKNOWN_VERB.to_owned(),
            table: String::new(),
        };
    };
    // A statement shape with no dangerous verb of its own (`SET`, `BEGIN`,
    // `VACUUM`, `VALUES`, …) keeps the classification it has always had.
    classify_statement(statement).unwrap_or_else(|| parse_sql_heuristic(query))
}

/// Where `verb` sits in [`VERB_PRECEDENCE`]; anything unlisted ranks last.
fn verb_rank(verb: &str) -> usize {
    VERB_PRECEDENCE
        .iter()
        .position(|v| *v == verb)
        .unwrap_or(usize::MAX)
}

/// The more dangerous of two candidate classifications, `a` winning a tie so the
/// caller can pass the statement's own verb first and its sub-queries after.
fn more_dangerous(a: Option<SqlFacts>, b: Option<SqlFacts>) -> Option<SqlFacts> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if verb_rank(&b.verb) < verb_rank(&a.verb) {
            b
        } else {
            a
        }),
        (a, b) => a.or(b),
    }
}

fn facts(verb: &str, table: String) -> Option<SqlFacts> {
    Some(SqlFacts {
        verb: verb.to_owned(),
        table,
    })
}

/// The relation an [`ObjectName`] names, normalized like [`clean_identifier`]:
/// schema qualifier dropped, quotes gone, lowercased. `public.users` → `users`.
fn relation_name(name: &ObjectName) -> String {
    name.0
        .last()
        .and_then(|part| part.as_ident())
        .map(|ident| ident.value.to_ascii_lowercase())
        .unwrap_or_default()
}

/// The relation a `FROM` item reads, when it is a plain named table.
fn table_factor_name(factor: &TableFactor) -> String {
    match factor {
        TableFactor::Table { name, .. } => relation_name(name),
        _ => String::new(),
    }
}

/// The one relation a statement names, or empty when it names several.
///
/// [`SqlFacts`] carries a single `table`, so for `DROP TABLE scratch, users` no
/// single value is right — and reporting the first is wrong in the dangerous
/// direction: an allow rule `sql.verb == 'DROP' && sql.table == 'scratch'` would
/// then authorize dropping `users` alongside it. Reporting nothing instead means
/// no table-scoped rule can match a multi-target statement, so only a
/// table-blind rule decides it. **Do not "simplify" this back to `.first()`.**
fn sole_relation<T>(targets: &[T], name_of: impl Fn(&T) -> String) -> String {
    match targets {
        [only] => name_of(only),
        _ => String::new(),
    }
}

/// Whether an `EXPLAIN` runs the statement it wraps.
///
/// `analyze` covers the bare `EXPLAIN ANALYZE …` spelling; PostgreSQL also takes
/// the flag as a utility option, `EXPLAIN (ANALYZE [ boolean ]) …`, which
/// sqlparser reports in `options` with `analyze` still false.
///
/// This is the one judgement here that can create a bypass rather than a false
/// refusal, so it defaults toward "executes": only an argument that is
/// *explicitly* false turns it off. A bare `ANALYZE`, `ANALYZE true`, and any
/// argument shape this does not recognize all count as executing.
fn explain_executes(analyze: bool, options: Option<&Vec<UtilityOption>>) -> bool {
    analyze
        || options.into_iter().flatten().any(|option| {
            option.name.value.eq_ignore_ascii_case("analyze")
                && !option_arg_is_false(option.arg.as_ref())
        })
}

/// Whether a utility option's argument is an explicit false. A missing argument
/// is not — `EXPLAIN (ANALYZE) …` executes.
fn option_arg_is_false(arg: Option<&Expr>) -> bool {
    match arg {
        Some(Expr::Value(value)) => match &value.value {
            Value::Boolean(flag) => !flag,
            Value::Number(digits, _) => digits == "0",
            Value::SingleQuotedString(text) => is_false_word(text),
            _ => false,
        },
        Some(Expr::Identifier(ident)) => is_false_word(&ident.value),
        _ => false,
    }
}

/// The words PostgreSQL's `parse_bool` reads as false, case-insensitively.
fn is_false_word(word: &str) -> bool {
    ["false", "off", "no", "0", "f", "n"]
        .iter()
        .any(|false_word| word.eq_ignore_ascii_case(false_word))
}

/// Whether a statement runs code honmoon cannot inspect and must therefore
/// refuse outright rather than classify.
///
/// Only `DO` today. A `DO` block executes an arbitrary PL/pgSQL body — measured
/// against PostgreSQL 17.11, `DO $$ BEGIN DELETE FROM sessions; END $$` really
/// does empty the table — while the statement itself reports the harmless verb
/// `DO`, so no `sql.verb` rule can see what it runs. Unlike `EXPLAIN ANALYZE`
/// there is nothing to unwrap: the body is PL/pgSQL rather than SQL, and
/// sqlparser 0.62 has no `DO` statement at all. Refusing is the fail-closed
/// answer, and matches what the runtime already does with a batch or a frame it
/// cannot parse.
///
/// Deliberately narrow. `CALL`, `EXECUTE` and `COPY` raise the same question and
/// are tracked separately (#103); whether to refuse them is a product decision,
/// not this predicate's.
pub fn is_uninspectable_statement(query: &str) -> bool {
    // sqlparser rejects `DO` outright, so there is no AST node to match on: the
    // leading keyword, past any comment prologue, is what identifies it.
    parse_sql_heuristic(query).verb == "DO"
}

/// Classify one parsed statement, or `None` when it carries no verb this module
/// models — the caller then keeps the pre-parser classification for it.
fn classify_statement(statement: &Statement) -> Option<SqlFacts> {
    match statement {
        // `EXPLAIN ANALYZE` *runs* the statement it wraps, so that statement is
        // what policy has to see; a plain `EXPLAIN` only plans it and stays an
        // `EXPLAIN`. PostgreSQL also spells the flag as a utility option
        // (`EXPLAIN (ANALYZE [ boolean ]) …`), value and all — see
        // [`explain_executes`]. The wrapped statement may itself be a CTE query,
        // so recurse rather than classifying it one level deep.
        Statement::Explain {
            analyze,
            options,
            statement,
            ..
        } => {
            if explain_executes(*analyze, options.as_ref()) {
                classify_statement(statement)
            } else {
                facts("EXPLAIN", String::new())
            }
        }
        Statement::Query(query) => classify_query(query),
        Statement::Insert(insert) => facts(
            "INSERT",
            match &insert.table {
                TableObject::TableName(name) => relation_name(name),
                _ => String::new(),
            },
        ),
        Statement::Delete(delete) => {
            let (FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables)) =
                &delete.from;
            facts(
                "DELETE",
                sole_relation(tables, |table| table_factor_name(&table.relation)),
            )
        }
        Statement::Update(update) => facts("UPDATE", table_factor_name(&update.table.relation)),
        Statement::Drop { names, .. } => facts("DROP", sole_relation(names, relation_name)),
        Statement::Truncate(truncate) => facts(
            "TRUNCATE",
            sole_relation(&truncate.table_names, |target| relation_name(&target.name)),
        ),
        Statement::AlterTable(alter) => facts("ALTER", relation_name(&alter.name)),
        Statement::Merge(merge) => facts("MERGE", table_factor_name(&merge.table)),
        _ => None,
    }
}

/// Classify a query, letting a data-modifying CTE outrank the outer `SELECT`:
/// `WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x` executes the `DELETE`,
/// so reporting the `SELECT` would hide it from every `sql.verb` rule.
fn classify_query(query: &Query) -> Option<SqlFacts> {
    let ctes = query
        .with
        .iter()
        .flat_map(|with| &with.cte_tables)
        .fold(None, |worst, cte| {
            more_dangerous(worst, classify_query(&cte.query))
        });
    more_dangerous(classify_set_expr(&query.body), ctes)
}

fn classify_set_expr(body: &SetExpr) -> Option<SqlFacts> {
    match body {
        SetExpr::Select(select) => facts(
            "SELECT",
            select
                .from
                .first()
                .map(|table| table_factor_name(&table.relation))
                .unwrap_or_default(),
        ),
        SetExpr::Query(query) => classify_query(query),
        SetExpr::Insert(statement)
        | SetExpr::Update(statement)
        | SetExpr::Delete(statement)
        | SetExpr::Merge(statement) => classify_statement(statement),
        SetExpr::SetOperation { left, right, .. } => {
            more_dangerous(classify_set_expr(left), classify_set_expr(right))
        }
        // `VALUES …` and `TABLE t`: no verb in `VERB_PRECEDENCE`, so they keep
        // the classification they had before the parser landed.
        //
        // A derived table or scalar subquery is deliberately *not* descended
        // into looking for a nested data-modifying CTE. PostgreSQL refuses to
        // run one: `SELECT * FROM (WITH y AS (DELETE FROM t RETURNING *) SELECT
        // * FROM y) z` fails with `ERROR: WITH clause containing a
        // data-modifying statement must be at the top level`. There is nothing
        // to catch there, so recursing would only add a way to misclassify.
        _ => None,
    }
}

/// The leading-token classifier honmoon shipped before `sqlparser`, kept as the
/// fallback for input the real grammar rejects.
///
/// Heuristic, not a full SQL grammar — enough to drive policy on the dangerous
/// verbs (`DROP`, `TRUNCATE`, `DELETE`, `UPDATE`, `INSERT`, `SELECT`). A verb it
/// does not recognize is reported as-is and carries no table; recognizing a verb
/// is not a precondition for allowing a statement, so ordinary traffic (`WITH`,
/// `EXPLAIN`, `SET`, `BEGIN`, …) is unaffected. An unclassifiable statement gets
/// [`UNKNOWN_VERB`].
fn parse_sql_heuristic(query: &str) -> SqlFacts {
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
/// uninspected.
///
/// PostgreSQL's own grammar (`sqlparser`) decides where the statement boundaries
/// are, so the answer is exact on anything it can read. Input it rejects falls
/// back to [`scan_for_statement_separator`], the byte scanner that shipped before
/// it, which errs toward "multiple" on anything it cannot follow — so on
/// unparseable input the behaviour is exactly what ships today, and no path
/// through this function is more permissive than that scanner alone.
pub fn carries_multiple_statements(query: &str) -> bool {
    match Parser::parse_sql(&PostgreSqlDialect {}, query) {
        Ok(statements) => statements.len() > 1,
        Err(_) => scan_for_statement_separator(query),
    }
}

/// Byte-level scan for a statement separator outside a literal, quoted
/// identifier, dollar-quoted body or comment. Deliberately conservative: it
/// answers "multiple" whenever it loses track of where the statement ends.
fn scan_for_statement_separator(query: &str) -> bool {
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
                // `E'…'` additionally honours backslash escapes, so its `\'` does
                // not close the string. A plain `'…'` is standard-conforming
                // (the default since 9.1): a backslash there is a literal
                // character, and reading it as an escape would make the scanner
                // skip the real closing quote — a miss in the unsafe direction.
                let backslash_escapes = quote == b'\'' && opens_escape_string(bytes, i);
                i += 1;
                loop {
                    match bytes.get(i) {
                        // Unterminated: honmoon cannot tell where the statement
                        // ends, so it is not inspectable.
                        None => return true,
                        Some(b'\\') if backslash_escapes => i += 2,
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
        // PostgreSQL's lexer ends a `--` comment at CR *or* LF (`scan.l`:
        // `"--"{non_newline}*` over `non_newline [^\n\r]`), so a lone CR ends it
        // too — searching only for LF would swallow `-- x<CR>; DROP TABLE users`
        // whole and miss the separator the server acts on. The terminator itself
        // is left in place; it is whitespace to every caller, and stopping at the
        // CR is also what makes CRLF come out right.
        (b'-', Some(b'-')) => Some(
            match bytes[start..]
                .iter()
                .position(|b| *b == b'\n' || *b == b'\r')
            {
                Some(end) => (start + end, true),
                None => (bytes.len(), true),
            },
        ),
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

/// Whether the quote at `start` opens an `E'…'` escape string.
///
/// Only that form treats a backslash as an escape. `U&'…'` reserves the
/// backslash for Unicode code points and still writes an embedded quote as `''`,
/// and `B'…'`/`X'…'` hold only bit and hex digits — so the doubled-quote rule
/// already covers all three.
fn opens_escape_string(bytes: &[u8], start: usize) -> bool {
    let Some(prev) = start.checked_sub(1) else {
        return false;
    };
    matches!(bytes.get(prev), Some(b'E' | b'e')) && !starts_identifier_continuation(bytes, prev)
}

/// Whether the byte before `start` is an identifier character, i.e. whatever is
/// at `start` continues a name rather than starting a new token.
fn starts_identifier_continuation(bytes: &[u8], start: usize) -> bool {
    start
        .checked_sub(1)
        .and_then(|prev| bytes.get(prev))
        .is_some_and(|c| is_identifier_cont(*c))
}

/// One byte of `ident_cont` as PostgreSQL's lexer defines it:
/// `[A-Za-z\200-\377_0-9\$]`. **Every** byte from `\200` up counts, so a
/// non-ASCII letter continues an identifier — an ASCII-only test here would let
/// `SELECT 1 AS é$tag$; DROP …$tag$` hide its separator inside a dollar quote
/// that PostgreSQL never opens.
fn is_identifier_cont(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' || byte >= 0x80
}

/// If a `$` at `start` opens a dollar quote (`$$` or `$tag$`), the index just
/// past its opening delimiter; `None` when it is something else.
fn dollar_tag_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    while let Some(&c) = bytes.get(i) {
        match c {
            b'$' => return Some(i + 1),
            // A tag follows the unquoted-identifier rules, so it may hold
            // non-ASCII bytes but may not *start* with a digit — that is a
            // positional parameter, not a tag.
            b'0'..=b'9' if i == start + 1 => return None,
            c if is_identifier_cont(c) && c != b'$' => i += 1,
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
        // A CTE query is classified by what it executes, not by its leading
        // keyword: PostgreSQL runs a SELECT here, so `sql.verb == 'SELECT'` is
        // the rule that should match it. (It used to report `WITH`, which no
        // rule about reads would ever have matched.)
        assert_eq!(
            parse_sql("with x as (select 1) select * from x").verb,
            "SELECT"
        );
    }

    #[test]
    fn explain_analyze_reports_the_statement_it_executes() {
        // `ANALYZE` makes PostgreSQL *run* the DELETE, so a `sql.verb ==
        // 'DELETE'` deny rule has to see a DELETE — not the EXPLAIN wrapper.
        let facts = parse_sql("EXPLAIN ANALYZE DELETE FROM sessions");
        assert_eq!(facts.verb, "DELETE");
        assert_eq!(facts.table, "sessions");
    }

    #[test]
    fn explain_without_analyze_stays_an_explain() {
        // Without `ANALYZE` the inner statement is only planned, never run, so
        // unwrapping it would refuse a harmless plan inspection.
        let facts = parse_sql("EXPLAIN DELETE FROM sessions");
        assert_eq!(facts.verb, "EXPLAIN");
        assert_eq!(facts.table, "");
    }

    #[test]
    fn explain_analyze_is_recognized_in_the_option_list_form() {
        // `EXPLAIN (ANALYZE, BUFFERS) …` executes just as `EXPLAIN ANALYZE`
        // does; the parser reports that spelling as a utility option instead.
        let facts = parse_sql("EXPLAIN (ANALYZE, BUFFERS) DELETE FROM sessions");
        assert_eq!(facts.verb, "DELETE");
        assert_eq!(facts.table, "sessions");
    }

    #[test]
    fn a_data_modifying_cte_outranks_the_outer_select() {
        // The DELETE inside the CTE executes, so it — and its table — is what
        // the facts must carry.
        let facts = parse_sql("WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x");
        assert_eq!(facts.verb, "DELETE");
        assert_eq!(facts.table, "t");
    }

    #[test]
    fn a_merge_cte_outranks_the_outer_select() {
        // PostgreSQL 17 allows MERGE as a data-modifying CTE and runs it:
        // against a 7-row table this statement left 5, so the MERGE deleted
        // rows while the facts said `SELECT`. It must report the MERGE.
        let facts = parse_sql(
            "WITH x AS (MERGE INTO t USING s ON t.id = s.id \
             WHEN MATCHED THEN DELETE RETURNING t.id) SELECT * FROM x",
        );
        assert_eq!(facts.verb, "MERGE");
        assert_eq!(facts.table, "t");
    }

    #[test]
    fn a_top_level_merge_carries_its_target_table() {
        // One MERGE can delete, update and insert, so it outranks each of them
        // — and it now names the relation it writes, which the leading-token
        // heuristic never extracted.
        let facts = parse_sql("MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE");
        assert_eq!(facts.verb, "MERGE");
        assert_eq!(facts.table, "t");
    }

    #[test]
    fn the_analyze_option_is_read_as_a_boolean_not_a_flag() {
        // Measured on PostgreSQL 17.11: `EXPLAIN (ANALYZE false) DELETE …` left
        // all 5 rows in place, so unwrapping it would refuse a plan inspection
        // that never runs. The other two spellings do execute.
        assert_eq!(
            parse_sql("EXPLAIN (ANALYZE false) DELETE FROM sessions").verb,
            "EXPLAIN"
        );
        assert_eq!(
            parse_sql("EXPLAIN (ANALYZE true) DELETE FROM sessions").verb,
            "DELETE"
        );
        assert_eq!(
            parse_sql("EXPLAIN (ANALYZE) DELETE FROM sessions").verb,
            "DELETE"
        );
    }

    #[test]
    fn a_multi_target_drop_or_truncate_names_no_table() {
        // `DROP TABLE a, b` drops both (measured: neither survived), so naming
        // only `a` would let an allow rule scoped to a harmless table authorize
        // the rest of the list. With no table, only a table-blind rule decides.
        let dropped = parse_sql("DROP TABLE a, b");
        assert_eq!(dropped.verb, "DROP");
        assert_eq!(dropped.table, "");

        let truncated = parse_sql("TRUNCATE a, b");
        assert_eq!(truncated.verb, "TRUNCATE");
        assert_eq!(truncated.table, "");

        // A single target is unchanged.
        assert_eq!(parse_sql("DROP TABLE a").table, "a");
    }

    #[test]
    fn a_do_block_is_uninspectable() {
        // The body is PL/pgSQL, not SQL: measured on PostgreSQL 17.11 this
        // emptied a 5-row table while the facts said the verb was `DO`.
        assert!(is_uninspectable_statement(
            "DO $$ BEGIN DELETE FROM sessions; END $$"
        ));
        assert!(is_uninspectable_statement(
            "/* audit */ do $$ begin delete from users; end $$"
        ));
        // Ordinary statements stay inspectable and are decided by rules.
        assert!(!is_uninspectable_statement("SELECT * FROM orders"));
        assert!(!is_uninspectable_statement("DROP TABLE users"));
        assert!(!is_uninspectable_statement(""));
    }

    #[test]
    fn a_read_only_cte_is_not_upgraded() {
        // Nothing here modifies data, so the query stays a SELECT over `x`.
        let facts = parse_sql("WITH x AS (SELECT 1) SELECT * FROM x");
        assert_eq!(facts.verb, "SELECT");
        assert_eq!(facts.table, "x");
    }

    #[test]
    fn unparseable_input_falls_back_to_the_shipped_scanners() {
        // `DROP INDEX CONCURRENTLY` and an unterminated comment are both beyond
        // sqlparser, so both must keep answering exactly as they did before it:
        // the token heuristic's verb/table, and the byte scanner's conservative
        // "this could be a batch".
        assert!(
            Parser::parse_sql(&PostgreSqlDialect {}, "DROP INDEX CONCURRENTLY idx_a").is_err(),
            "test input must actually be unparseable"
        );
        let facts = parse_sql("DROP INDEX CONCURRENTLY idx_a");
        assert_eq!(facts.verb, "DROP");
        assert_eq!(facts.table, "idx_a");

        assert!(
            Parser::parse_sql(&PostgreSqlDialect {}, "SELECT 1; /* unterminated").is_err(),
            "test input must actually be unparseable"
        );
        assert!(carries_multiple_statements("SELECT 1; /* unterminated"));
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
    fn a_non_ascii_identifier_byte_still_blocks_a_dollar_quote() {
        // `é` is `ident_cont` to PostgreSQL, so `é$tag$` is one identifier and
        // the `;` that follows is a real separator.
        assert!(carries_multiple_statements(
            "SELECT 1 AS é$tag$; DROP TABLE users$tag$"
        ));
        // Separated from the identifier, the same `$tag$` genuinely opens a
        // dollar-quoted body, and the `;` inside it is not a separator.
        assert!(!carries_multiple_statements(
            "SELECT é, $tag$a; b$tag$ FROM orders"
        ));
        // A tag may itself be non-ASCII. Failing to recognize one would leave
        // its body scanned as bare SQL, where a `--` inside it would comment out
        // the separator that follows.
        assert!(!carries_multiple_statements(
            "SELECT $é$a; b$é$ FROM orders"
        ));
        assert!(carries_multiple_statements(
            "SELECT $é$--$é$; DROP TABLE users"
        ));
    }

    #[test]
    fn a_line_comment_ends_at_cr_as_well_as_lf() {
        // PostgreSQL ends the comment at the CR and runs the DROP, so a scanner
        // that only knows LF would call this one statement and forward it.
        assert!(carries_multiple_statements(
            "SELECT 1 -- x\r; DROP TABLE users"
        ));
        assert!(carries_multiple_statements(
            "SELECT 1 -- x\r\n; DROP TABLE users"
        ));
        // The ordinary shapes are unchanged: LF-terminated, and running to EOF.
        assert!(!carries_multiple_statements(
            "SELECT 1 -- x\nFROM orders WHERE a = 1"
        ));
        assert!(!carries_multiple_statements(
            "SELECT 1 -- x; not a statement"
        ));
        assert_eq!(parse_sql("-- audit\rDROP TABLE users").verb, "DROP");
    }

    #[test]
    fn backslash_escapes_are_honoured_only_in_an_e_string() {
        // `\'` does not close an `E'…'`, so this is one statement.
        assert!(!carries_multiple_statements(r"SELECT E'a\'b' FROM orders"));
        assert!(!carries_multiple_statements(
            r"SELECT e'a\'; b' FROM orders"
        ));
        // A real batch behind an E-string is still caught.
        assert!(carries_multiple_statements(
            r"SELECT E'a\'b'; DROP TABLE users"
        ));
        // A plain string is standard-conforming: the backslash is a literal, so
        // the quote after it really does close the string.
        assert!(carries_multiple_statements(
            r"SELECT 'a\'; DROP TABLE users"
        ));
        assert!(!carries_multiple_statements(r"SELECT 'a\' FROM orders"));
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
