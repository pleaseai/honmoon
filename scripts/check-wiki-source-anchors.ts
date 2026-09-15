/**
 * Resolve every `#L` source anchor in the wiki against the file it cites.
 *
 * `wiki/AGENTS.md` makes citations a hard convention — "Every architectural
 * claim needs a source" — and spells them
 * `[path:line](…/blob/main/path#Lline)`. A line range is the one part of that
 * convention nothing in the repository was holding: the cited file goes on
 * being edited, code moves down, and the anchor a page was written against ends
 * up naming a closing `}` or the blank line between two items. A citation that
 * lands there supports nothing, and the reader who checks one and finds nothing
 * has no reason to trust the next.
 *
 * It is not a hypothetical decay. #204 tabulated six on
 * `getting-started/policy-authoring.md` alone; anchors went stale three times
 * inside PR #201, twice from that PR's *own* commits moving code under links it
 * had just written. #169 and #192 are the same failure on `engine.rs`. Every
 * one of those was caught — or missed — by a human opening the link.
 *
 * ## What it enforces
 *
 * Five rules about a citation, and they are narrow on purpose:
 *
 * 1. **The cited file is there.** The path in the URL has to resolve to a
 *    regular file inside the repository. Checked for every blob link, with or
 *    without a fragment — a page citing a file that was deleted or renamed is
 *    the same defect with a coarser anchor.
 * 2. **The range is inside the file.** `1 ≤ start ≤ end ≤ last line`. This is
 *    what catches a file that *shrank*: `quick-start.md` cited
 *    `gateway.rs#L206-L271` against a 265-line file.
 * 3. **The range starts on something.** Its first line is not blank and is not
 *    a bare closing delimiter (`}`, `];`, `});` …). That pair is the signature
 *    of code moving down out from under a link: the range slides off the item
 *    it was written for and onto the end of the one above.
 * 4. **The link text agrees with the URL.** Text spelled `name:12-34` has to
 *    carry the same numbers as the `#L12-L34` it links to, and a link with no
 *    `#L` fragment at all must not have text promising one. A reader reads the
 *    text and rarely the href, so the two drifting apart is a citation that
 *    misleads without being followed.
 * 5. **The link is to `main`.** A pinned-SHA permalink is reported rather than
 *    resolved, because this reads the working tree: answering a question about
 *    one revision with another revision's lines is the failure it exists to
 *    stop. Decided from the URL alone, unlike the four above.
 *
 * And two rules about the scan rather than about any one citation, because
 * without them the failure mode is a vacuous pass — a run that reports nothing
 * because it read nothing (`checkCoverage` in `check-wiki-io-claim.ts` is the
 * same guard for the same reason):
 *
 * 6. **Every blob link was read.** A `](…/blob/…)` occurrence the anchor
 *    pattern cannot parse is reported per document, because a citation that
 *    does not match is not merely unchecked — it is invisible, absent from the
 *    resolved count and unable to produce a finding. Review kept finding shapes
 *    that fell out this way and another will be written eventually; this rule
 *    is what makes them loud rather than the pattern being widened once per
 *    shape. It only works while the *counter* sees more than the parser, so
 *    {@link BLOB_LINK} is deliberately the looser of the two — a reference
 *    definition and a destination on the next line are counted here and
 *    resolved nowhere, which is a report rather than a silence.
 * 7. **The scan reached the published wiki.** Every page `llms-full.txt`
 *    inlines has to be a document the scan opened. `wikiDocuments()` finds
 *    pages by glob, so a directory rename or a pattern regression can shrink
 *    the set silently, and the bundle's own `<doc path="…">` list is the
 *    independent witness.
 *
 * ## What it does not enforce, so it is not read as more than it is
 *
 * **It never reads the claim.** Rule 3 is a heuristic about where a range
 * begins — not a proof that what the range *shows* supports the sentence
 * attached to it. An anchor that starts on a plausible `fn` line and displays
 * a completely unrelated function passes every rule here. That is exactly the
 * drift #169 and #192 tabulate — `engine.rs:81-89` cited as `matches_domain()`
 * while showing the `decide_with` body — and this check does not find it.
 * Nothing mechanical can: it would have to know what the prose means.
 *
 * Rule 3 is also one-sided. It judges the first line only, so a range whose
 * far *end* has slid onto the next item is not flagged, and one that starts on
 * a doc comment belonging to the previous item reads as fine. Rule 4 fires only
 * on text that spells its own line numbers; `[gateway.rs]` linked to `#L1-L9`
 * carries no numbers to disagree with.
 *
 * Nothing here is markdown-aware. A citation inside a fenced code block — an
 * example of the convention rather than a claim under it — is resolved like any
 * other, and `check-wiki-io-claim.ts` reads fenced prose the same way. No
 * published page does that today; if one comes to, the example has to be
 * spelled so it resolves, or this has to learn about fences.
 *
 * The same line bounds rules 1-6 in the other direction: **a destination is
 * read as it is written.** Markdown resolves a character reference or a
 * percent-encoding in the URL — `https://github&#46;com/…` links to the same
 * page — and neither {@link ANCHOR} nor {@link BLOB_LINK} sees through one, so
 * such a citation is neither counted nor resolved. The shapes that *are* read
 * are the ones ordinary writing produces: the angle-bracketed destination
 * CommonMark allows, the whitespace it permits on either side of one, and the
 * permalinks GitHub's own copy button emits. An encoded host is not one of
 * those; nobody types it by accident, and seeing through the general case means
 * decoding destinations with a markdown parser. This is a floor under review of
 * documentation written in good faith, not a gate against a citation spelled to
 * evade it — which a page could do far more simply by carrying no link at all,
 * since nothing here can require one.
 *
 * So this is a floor under review, not a replacement for it — the same split
 * `check-wiki-io-claim.ts` draws for the I/O claim. What it buys is that the
 * half of #204 a machine *can* decide cannot come back silently, including from
 * a commit in the pull request that fixed it.
 *
 * ## Anchors that are known-stale and belong to another issue
 *
 * {@link TRACKED} carries the ones already filed elsewhere. They are listed,
 * counted and attributed on every run rather than skipped — an entry names the
 * issue that owns re-anchoring it — and an entry that stops matching anything
 * fails, so the list cannot outlive the drift it describes.
 *
 * It is a ledger of open work, not an exemption, and the bound on that is
 * exact: an entry suppresses the anchor it names **on the pages it names**, so
 * the same anchor written onto a page the entry does not list is reported like
 * any other, and a page that stops producing the finding is reported as a page
 * to drop. What it cannot tell apart is a *new* citation that coincides with
 * a tracked one on the same page — same file, same range, same rule — which
 * reads as the tracked occurrence. Read the guarantee as "the rules above,
 * applied to every citation outside the ledger's own pages", and not as
 * anything about the drift those rules cannot see.
 *
 * `llms-full.txt` is scanned with the pages, for the reason
 * `check-wiki-io-claim.ts` scans it: it is generated
 * (`wiki/.vitepress/gen-llms-full.mjs`) and inlines every page, so a page
 * repointed without regenerating it leaves the stale anchor in the file LLM
 * readers actually consume. Its occurrences are judged against the page each
 * was generated from, which the bundle's own `<doc path="…">` markers name.
 *
 * It is enforced by its own test rather than by a `ci.yml` step, the way
 * `check-wiki-io-claim.ts` is: it reads the working tree and needs no build, so
 * `bun test` in the `js` job is already the job that runs it, and a contributor
 * running the suite locally gets the same answer CI will.
 *
 * Usage:
 *   bun scripts/check-wiki-source-anchors.ts
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import process from 'node:process'
import { realPathInside } from './check-dashboard-csp'
import { checkCoverage, REPO_ROOT, wikiDocuments } from './check-wiki-io-claim'

export { REPO_ROOT }

/**
 * Blob links into this repository, with an optional `#L` fragment.
 *
 * The ref is captured rather than pinned to `main` so a pinned-SHA permalink is
 * reported rather than silently resolved against the working tree, which would
 * answer a question about one revision with another revision's lines.
 *
 * Two shapes GitHub's own "copy permalink" emits are accepted rather than left
 * to fall out: a `?plain=1` query before the fragment, and the column-qualified
 * `#L12C3-L34C10` a partial multi-line selection produces. Columns are read and
 * discarded — they narrow which characters are highlighted, not which lines are
 * cited, and it is the lines this resolves. A contributor pasting either would
 * otherwise have a working link reported as broken, and a guard that refuses
 * working input is the failure `check-dashboard-csp.ts` names as its own worst
 * case. Everything still unparseable is reported by {@link checkLinksRead}
 * rather than disappearing, so widening this is a convenience and not the
 * safety net.
 *
 * A third shape is accepted for a different reason. CommonMark lets a
 * destination be wrapped in angle brackets — `[text](<https://…#L1>)` — and
 * VitePress renders it as an ordinary link. Unwidened, that citation matched
 * neither this pattern *nor* {@link BLOB_LINK}, so it was not merely
 * unparseable, it was uncounted: rule 6 saw zero links and zero anchors and
 * reported nothing. That is the one way a citation can be invisible to both
 * halves at once, which is why it is read here rather than left to the net.
 * Angle brackets are also why the ref, path and query stop at `>`. A
 * destination with a space inside the brackets — legal there and nowhere else —
 * still does not parse, and that one is caught by rule 6, having been counted.
 *
 * The horizontal whitespace CommonMark permits between `](` and the
 * destination, and between the destination and `)`, is read for the same
 * reason and one more: `]( https://…)` is a typo rather than a decision, and a
 * stray space is the likeliest way a real page ends up in a shape neither
 * pattern sees. Spaces and tabs only. A newline is legal there too, and
 * {@link BLOB_LINK} deliberately allows it where this does not — the counter
 * is looser than the parser on purpose, so the shape lands as a rule 6 report
 * rather than as silence.
 *
 * The link text stops at a newline and at 200 characters. Both bound the
 * backtracking: without them the engine retries every `[` in the document and
 * scans to end-of-input before failing. Measured on 200KB of bare `[`, that was
 * 47.9s unbounded and is 99ms bounded — linear, and a build-time stall a fork's
 * pull request could have added markdown to cause. The longest link text in the
 * wiki today is 66 characters and none spans a line, so the bound costs
 * nothing; a text that exceeds it stops matching here and is reported by
 * {@link checkLinksRead} instead.
 *
 * It does not make every input linear, and the residue is named rather than
 * implied: 200KB of a *partial* prefix (`[x](https://github.com/pleaseai/`…)
 * still measured 1.7s, because each attempt fails inside the literal rather
 * than inside the text group. That is superlinear and small, it is the shape a
 * document would have to be written on purpose to hit, and the bound above is
 * not what would fix it.
 */
const ANCHOR
  = /\[([^\]\n]{0,200})\]\([ \t]*<?https:\/\/github\.com\/pleaseai\/honmoon\/blob\/([^/)>]+)\/([^)?#\s>]+)(?:\?[^)#\s>]*)?(?:#L(\d+)(?:C\d+)?(?:-L(\d+)(?:C\d+)?)?)?>?[ \t]*\)/g

/**
 * A markdown link into this repository's blob tree, counted but not parsed.
 *
 * Deliberately just the `](` and the prefix: it is what {@link ANCHOR} has to
 * account for, so the two disagreeing is the signal rule 6 reports. Where the
 * two differ, this one is deliberately the looser — a shape only the parser
 * rejects is reported, while a shape *neither* sees is silent — so it takes
 * any whitespace after the `](`, including the newline {@link ANCHOR} refuses,
 * and it counts a reference *definition* (`[label]: …/blob/…`) as well as an
 * inline link. Neither the definition nor the `[text][label]` that uses it is
 * resolved, and that is the point: rule 6 reports the document, and the page
 * spells the citation inline. It counts a literal host, bare or
 * angle-bracketed. What it does not see through is an encoded destination
 * (`github&#46;com`, a percent-encoding); the module doc says why that bound is
 * where it is. A bare URL in prose is not a citation either pattern reads, and
 * is not counted as one.
 */
const BLOB_LINK = /\](?:\(|:)\s*<?https:\/\/github\.com\/pleaseai\/honmoon\/blob\//g

/** A line holding nothing but the end of the item above it. */
const BARE_DELIMITER = /^[)\]}]+[,;]?$/

/** Link text that spells its own line numbers, e.g. `lib.rs:57-152`. */
const TEXT_LINES = /:(\d+)(?:-(\d+))?$/

/**
 * The marker `gen-llms-full.mjs` writes ahead of each inlined page.
 *
 * Anchored at column 1, because the generator emits it there and a `<doc …>`
 * quoted inside a page's prose would otherwise re-attribute everything under
 * it. `path` is repo-relative and already carries the `wiki/` prefix, so it
 * compares directly against an {@link Anchor}'s `where`.
 */
const BUNDLE_DOC = /^<doc\s[^>]*\bpath="([^"]+)"/

/** The marker that closes one, likewise at column 1. */
const BUNDLE_DOC_END = /^<\/doc>/

/**
 * Which rule a finding came from — {@link TRACKED} matches on it.
 *
 * `coverage` is the pair of rules about the scan (6 and 7). It is never a
 * {@link Tracked} key: an entry exists to defer one citation to an issue, and
 * nothing about a scan that did not happen can be deferred.
 */
export type Kind = 'file' | 'ref' | 'range' | 'blank' | 'delimiter' | 'text' | 'coverage'

/** One citation, as written. */
export interface Anchor {
  /** Repo-relative path of the document the citation is in. */
  where: string
  /** 1-based line of that document the citation starts on. */
  line: number
  /** The link text. */
  text: string
  /** The `blob/<ref>` the URL names. */
  ref: string
  /** Repo-relative path the URL cites. */
  path: string
  /** First line of the cited range, or `null` for a whole-file citation. */
  start: number | null
  /** Last line of the cited range; equals `start` for a single-line anchor. */
  end: number | null
}

export interface Problem {
  where: string
  /** The document line, or `null` for a finding about the document as a whole. */
  line: number | null
  kind: Kind
  detail: string
}

/**
 * An anchor known to be stale, whose re-anchoring is filed somewhere else.
 *
 * Keyed by the anchor itself rather than by the page, because one anchor lives
 * in two documents — the page and the `llms-full.txt` bundle that inlines it —
 * and a second entry for the copy would rot independently of the first.
 *
 * `kind` is part of the key so an entry cannot quietly absorb a *worse* finding
 * about the same anchor: an entry recorded for a range that starts on a blank
 * line stops matching if that range later falls off the end of a shrinking
 * file, and the range failure is reported.
 */
/** One `<doc>…</doc>` span of `llms-full.txt`, and the page it came from. */
export interface Section {
  /** 1-based line of the opening marker. */
  line: number
  /** 1-based line of the closing marker; equals `line` while unterminated. */
  end: number
  /** Repo-relative path of the page, as the marker spells it. */
  page: string
}

export interface Tracked {
  path: string
  start: number
  end: number
  kind: Kind
  /** The issue that owns re-anchoring it. */
  issue: number
  /**
   * The page(s) under `wiki/` the entry defers, relative to `wiki/`.
   *
   * Part of the match, not a note. Keyed by anchor alone the ledger leaked two
   * ways, both found in review: the same stale anchor copied onto a *new* page
   * read as the tracked occurrence and was accepted, and an occurrence on any
   * page at all kept an entry alive after the page the issue is about had
   * dropped it. An entry defers the pages it names and nothing else.
   *
   * The `llms-full.txt` bundle is not listed. It is generated from these pages,
   * so each of its occurrences is attributed to the page whose `<doc path="…">`
   * section holds it and deferred only while the entry still matches *that*
   * page — which makes a page repointed without regenerating the bundle two
   * findings (a stale page on the entry and an unread bundle citation) rather
   * than none, even when a sibling page here still carries the old anchor.
   */
  pages: string[]
}

export interface Report {
  problems: Problem[]
  tracked: { entry: Tracked, where: string, line: number }[]
  /**
   * Pages an entry names on which no citation produces its finding any more.
   *
   * Per page rather than per entry: an entry listing three pages where one was
   * repointed is two-thirds live, and dropping only the dead page is the edit
   * a reader has to make.
   */
  stale: { entry: Tracked, page: string }[]
  /** How many anchors were resolved, so a vacuous pass is visible. */
  resolved: number
}

/** Every citation in one document, in the order they appear. */
export function parseAnchors(source: string, where: string): Anchor[] {
  const anchors: Anchor[] = []
  for (const match of source.matchAll(ANCHOR)) {
    const [, text, ref, path, start, end] = match
    const first = start === undefined ? null : Number(start)
    anchors.push({
      where,
      line: source.slice(0, match.index).split('\n').length,
      text: text!,
      ref: ref!,
      path: path!,
      start: first,
      end: first === null ? null : end === undefined ? first : Number(end),
    })
  }
  return anchors
}

/**
 * The cited file's lines, or why it could not be read.
 *
 * The path comes out of a markdown link, so it is a string this script did not
 * write; `realPathInside` is what bounds opening it to the repository, the same
 * boundary the dashboard guards use for a specifier they did not write (#233).
 * Every outcome it can return is reported rather than skipped — a citation
 * whose target cannot be read is a citation that supports nothing, which is the
 * finding, not a reason to move on.
 */
export function readCited(path: string): { lines: string[] } | { detail: string } {
  const real = realPathInside(REPO_ROOT, join(REPO_ROOT, path))
  if ('missing' in real) {
    return { detail: `cites \`${path}\`, which is not in the repository` }
  }
  if ('reason' in real) {
    return { detail: `cites \`${path}\`, which ${real.reason}` }
  }
  let text: string
  try {
    text = readFileSync(real.path, 'utf8')
  }
  catch (error) {
    return { detail: `cites \`${path}\`, which could not be read (${String(error)})` }
  }
  const lines = text.split('\n')
  // A file ending in a newline splits to a trailing empty element that is not a
  // line anyone can cite; `#L<last>` on GitHub is the last line with content.
  if (lines.at(-1) === '') {
    lines.pop()
  }
  return { lines }
}

/**
 * What is wrong with one citation, resolved against `cited` — the result
 * {@link readCited} returned for the path it names.
 *
 * At most one finding per citation, and the order is deliberate: a file that
 * cannot be read is not also judged for its range, and a range outside the file
 * is not also judged for its text. Each of those would be a second line about
 * one edit, and the first one is the one that has to be acted on.
 */
export function checkAnchor(
  anchor: Anchor,
  cited: { lines: string[] } | { detail: string },
): Problem | null {
  const at = { where: anchor.where, line: anchor.line }

  if (anchor.ref !== 'main') {
    return {
      ...at,
      kind: 'ref',
      detail: `links \`blob/${anchor.ref}\`, which this check cannot resolve — it reads the `
        + 'working tree, so only `main` anchors are verified here',
    }
  }
  if (!('lines' in cited)) {
    return { ...at, kind: 'file', detail: cited.detail }
  }

  const { lines } = cited
  const { start, end, path } = anchor
  const declared = TEXT_LINES.exec(anchor.text)

  // Rule 4 runs before the whole-file return below, not after it. Text that
  // spells a range the URL does not carry — `[lib.rs:100-120]` linked at the
  // file — is the mismatch this rule is about, in its worst form: the reader
  // is given precise lines and the link lands on none of them. Returning early
  // for `start === null` had it pass (found by gemini-code-assist and by the
  // silent-failure review on #254).
  if (start === null || end === null) {
    if (declared === null) {
      return null
    }
    return {
      ...at,
      kind: 'text',
      detail: `reads \`${anchor.text}\` but links no line range at all — a reader takes the text `
        + 'for the anchor and never follows the link',
    }
  }

  if (start < 1 || start > end || end > lines.length) {
    return {
      ...at,
      kind: 'range',
      detail: `cites \`${path}#L${start}-L${end}\`, which is not a range in a ${lines.length}-line file`,
    }
  }

  if (declared !== null) {
    const textStart = Number(declared[1])
    const textEnd = declared[2] === undefined ? textStart : Number(declared[2])
    if (textStart !== start || textEnd !== end) {
      return {
        ...at,
        kind: 'text',
        detail: `reads \`${anchor.text}\` but links \`#L${start}-L${end}\` — a reader takes the text `
          + 'for the anchor and never follows the link',
      }
    }
  }

  const first = lines[start - 1]!.trim()
  if (first === '') {
    return {
      ...at,
      kind: 'blank',
      detail: `starts \`${path}#L${start}\` on a blank line, so the range opens on nothing — `
        + 'the signature of code moving down out from under the link',
    }
  }
  if (BARE_DELIMITER.test(first)) {
    return {
      ...at,
      kind: 'delimiter',
      detail: `starts \`${path}#L${start}\` on \`${first}\`, which closes the item above it rather `
        + 'than opening the one the link text names',
    }
  }
  return null
}

/**
 * Anchors already known stale, whose re-anchoring is filed somewhere else.
 *
 * #119, #169 and #192 were open against specific pages before this check
 * existed. #253 is the rest, which nothing owned until the check enumerated
 * them: it splits them into the seventeen that merely open on the blank line
 * after a heading in a prose or config file and the eighteen where the range
 * has genuinely slid off the item in a source file.
 *
 * Every entry was resolved against `main` at `4208e94` — the commit that
 * repointed `getting-started/policy-authoring.md` — and each one is printed
 * with its issue number on every passing run. None of them is on that page:
 * #204's own anchors are fixed, not tracked, apart from the one `engine.rs`
 * row #169 tabulates.
 */
export const TRACKED: Tracked[] = [
  // #119
  { path: 'crates/honmoon-proxy/src/gateway.rs', start: 113, end: 153, kind: 'delimiter', issue: 119, pages: ['getting-started/quick-start.md'] },
  { path: 'crates/honmoon-proxy/src/gateway.rs', start: 206, end: 271, kind: 'range', issue: 119, pages: ['deep-dive/egress-gateway.md', 'getting-started/quick-start.md'] },

  // #169
  { path: 'crates/honmoon-core/src/engine.rs', start: 59, end: 60, kind: 'blank', issue: 169, pages: ['getting-started/policy-authoring.md'] },

  // #192
  { path: 'crates/honmoon-core/src/engine.rs', start: 23, end: 69, kind: 'delimiter', issue: 192, pages: ['deep-dive/policy-engine.md'] },
  { path: 'crates/honmoon-core/src/engine.rs', start: 444, end: 467, kind: 'delimiter', issue: 192, pages: ['deep-dive/policy-engine.md'] },

  // #253
  { path: '.please/docs/decisions/0002-phase1-connect-proxy-on-tokio.md', start: 10, end: 44, kind: 'blank', issue: 253, pages: ['deep-dive/roadmap-open-core.md', 'onboarding/staff-engineer-guide.md'] },
  { path: '.please/docs/decisions/0002-phase1-connect-proxy-on-tokio.md', start: 32, end: 44, kind: 'blank', issue: 253, pages: ['deep-dive/egress-gateway.md'] },
  { path: '.please/docs/knowledge/product.md', start: 6, end: 11, kind: 'blank', issue: 253, pages: ['getting-started/overview.md'] },
  { path: '.please/docs/knowledge/product.md', start: 6, end: 29, kind: 'blank', issue: 253, pages: ['onboarding/executive-guide.md'] },
  { path: '.please/docs/knowledge/product.md', start: 13, end: 18, kind: 'blank', issue: 253, pages: ['getting-started/overview.md', 'onboarding/executive-guide.md'] },
  { path: '.please/docs/knowledge/product.md', start: 31, end: 37, kind: 'blank', issue: 253, pages: ['onboarding/product-manager-guide.md'] },
  { path: '.please/docs/knowledge/workflow.md', start: 41, end: 96, kind: 'blank', issue: 253, pages: ['getting-started/installation.md'] },
  { path: '.please/docs/knowledge/workflow.md', start: 76, end: 81, kind: 'blank', issue: 253, pages: ['onboarding/contributor-guide.md'] },
  { path: 'Cargo.toml', start: 9, end: 14, kind: 'blank', issue: 253, pages: ['getting-started/installation.md'] },
  { path: 'Cargo.toml', start: 16, end: 28, kind: 'blank', issue: 253, pages: ['deep-dive/architecture.md'] },
  { path: 'README.md', start: 11, end: 17, kind: 'blank', issue: 253, pages: ['getting-started/overview.md'] },
  { path: 'crates/honmoon-core/src/lib.rs', start: 15, end: 25, kind: 'blank', issue: 253, pages: ['getting-started/overview.md'] },
  { path: 'crates/honmoon-core/src/lib.rs', start: 128, end: 132, kind: 'delimiter', issue: 253, pages: ['deep-dive/architecture.md'] },
  { path: 'crates/honmoon-core/src/protocols.rs', start: 95, end: 104, kind: 'delimiter', issue: 253, pages: ['deep-dive/protocol-parsing.md'] },
  { path: 'crates/honmoon-core/src/protocols.rs', start: 158, end: 176, kind: 'blank', issue: 253, pages: ['deep-dive/protocol-parsing.md'] },
  { path: 'crates/honmoon-core/src/protocols.rs', start: 248, end: 254, kind: 'blank', issue: 253, pages: ['deep-dive/protocol-parsing.md'] },
  { path: 'crates/honmoon-core/src/protocols.rs', start: 256, end: 273, kind: 'blank', issue: 253, pages: ['deep-dive/protocol-parsing.md'] },
  { path: 'crates/honmoon-core/src/protocols.rs', start: 275, end: 281, kind: 'delimiter', issue: 253, pages: ['deep-dive/protocol-parsing.md', 'onboarding/contributor-guide.md'] },
  { path: 'crates/honmoon-core/src/protocols.rs', start: 291, end: 299, kind: 'delimiter', issue: 253, pages: ['deep-dive/protocol-parsing.md'] },
  { path: 'crates/honmoon-core/src/protocols.rs', start: 308, end: 311, kind: 'blank', issue: 253, pages: ['deep-dive/protocol-parsing.md'] },
  { path: 'crates/honmoon-mgmt/src/lib.rs', start: 30, end: 36, kind: 'blank', issue: 253, pages: ['deep-dive/control-plane.md'] },
  { path: 'crates/honmoon-mgmt/src/lib.rs', start: 95, end: 97, kind: 'blank', issue: 253, pages: ['deep-dive/control-plane.md'] },
  { path: 'crates/honmoon-mgmt/src/lib.rs', start: 108, end: 110, kind: 'blank', issue: 253, pages: ['deep-dive/control-plane.md'] },
  { path: 'crates/honmoon-proxy/src/gateway.rs', start: 62, end: 65, kind: 'blank', issue: 253, pages: ['deep-dive/egress-gateway.md'] },
  { path: 'crates/honmoon-proxy/src/gateway.rs', start: 112, end: 162, kind: 'delimiter', issue: 253, pages: ['deep-dive/egress-gateway.md'] },
  { path: 'crates/honmoon-proxy/src/gateway.rs', start: 114, end: 161, kind: 'blank', issue: 253, pages: ['deep-dive/egress-gateway.md'] },
  { path: 'crates/honmoon-proxy/src/gateway.rs', start: 169, end: 201, kind: 'blank', issue: 253, pages: ['deep-dive/egress-gateway.md'] },
  { path: 'docs/business-model.md', start: 12, end: 18, kind: 'blank', issue: 253, pages: ['deep-dive/roadmap-open-core.md', 'onboarding/product-manager-guide.md'] },
  { path: 'docs/business-model.md', start: 24, end: 28, kind: 'blank', issue: 253, pages: ['onboarding/executive-guide.md', 'onboarding/product-manager-guide.md'] },
  { path: 'docs/business-model.md', start: 32, end: 44, kind: 'blank', issue: 253, pages: ['deep-dive/roadmap-open-core.md', 'onboarding/executive-guide.md', 'onboarding/staff-engineer-guide.md'] },
  { path: 'docs/business-model.md', start: 68, end: 74, kind: 'blank', issue: 253, pages: ['deep-dive/roadmap-open-core.md'] },
  { path: 'docs/business-model.md', start: 94, end: 98, kind: 'blank', issue: 253, pages: ['onboarding/executive-guide.md'] },
  { path: 'docs/roadmap.md', start: 93, end: 100, kind: 'blank', issue: 253, pages: ['deep-dive/roadmap-open-core.md'] },
  { path: 'packages/api/src/auth.ts', start: 102, end: 201, kind: 'delimiter', issue: 253, pages: ['deep-dive/control-plane.md'] },
  { path: 'packages/api/src/index.ts', start: 41, end: 43, kind: 'delimiter', issue: 253, pages: ['deep-dive/control-plane.md'] },
]

/** The generated bundle that inlines every published page. */
const LLMS_FULL = 'wiki/llms-full.txt'

/**
 * Whether `entry` defers this citation — the anchor, the rule, and the page.
 *
 * Split out because the page half is the part review found missing and the part
 * a regression would drop silently: matching on the anchor alone still passes
 * every other test in the suite while letting a stale anchor copied to a new
 * page through (greptile and codex both reported it on #254).
 */
export function defers(
  entry: Tracked,
  anchor: Anchor,
  kind: Kind,
  page: string = anchor.where,
): boolean {
  return entry.path === anchor.path
    && entry.start === anchor.start
    && entry.end === anchor.end
    && entry.kind === kind
    && entry.pages.some(listed => `wiki/${listed}` === page)
}

/**
 * Index `llms-full.txt` by the page each of its lines was generated from.
 *
 * One entry per `<doc path="…">…</doc>` section, in file order, carrying the
 * lines the section spans. The bundle is a concatenation of pages and a
 * deferral is per page ({@link defers}), so without the attribution a bundle
 * occurrence can only be matched by anchor — and review found what that costs:
 * for an entry naming several pages, one page repointed without regenerating
 * the bundle leaves its stale copy hiding behind another listed page that still
 * carries the same anchor.
 *
 * The **end** of a section is read, not assumed from where the next one starts.
 * Everything the generator writes outside a section — its header today, a
 * footer tomorrow — belongs to no page, so a citation there is reported rather
 * than attributed to whichever page happens to precede it. A `<doc>` with no
 * `</doc>` before the next one or the end of file spans only its own line, for
 * the same reason: a bundle this cannot read the shape of should defer nothing.
 */
export function bundleSections(source: string): Section[] {
  const sections: Section[] = []
  source.split('\n').forEach((text, index) => {
    const line = index + 1
    const open = BUNDLE_DOC.exec(text)
    if (open !== null) {
      sections.push({ line, end: line, page: open[1]! })
    }
    else if (BUNDLE_DOC_END.test(text) && sections.length > 0) {
      const last = sections[sections.length - 1]!
      if (last.end === last.line) {
        last.end = line
      }
    }
  })
  return sections
}

/**
 * The page a bundle line was generated from, or `null` when it falls outside
 * every section — the generator's own header, the blank line between two
 * sections, anything after the last `</doc>`.
 */
export function bundleOwner(sections: Section[], line: number): string | null {
  const section = sections.find(({ line: from, end }) => line >= from && line <= end)
  return section?.page ?? null
}

/**
 * Rule 6: blob links in one document that {@link ANCHOR} could not read.
 *
 * Counted rather than located, because a link the pattern does not match has no
 * parsed position to report. The count is the finding: it says how many
 * citations in this document went unresolved, and the document is small enough
 * to find them in.
 */
export function checkLinksRead(source: string, where: string): Problem[] {
  const links = [...source.matchAll(BLOB_LINK)].length
  const read = parseAnchors(source, where).length
  if (links <= read) {
    return []
  }
  return [{
    where,
    line: null,
    kind: 'coverage',
    detail: `carries ${links} link(s) into this repository and ${read} of them parsed as a `
      + `citation — ${links - read} went unresolved, and an unresolved citation is invisible `
      + 'here rather than merely unchecked. Spell it `[text](https://github.com/pleaseai/honmoon'
      + '/blob/main/<path>#L<a>-L<b>)`, or widen `ANCHOR` if the shape is one GitHub emits',
  }]
}

/**
 * Read every wiki document and resolve every citation in it.
 *
 * Two passes, because {@link Tracked} defers a citation on the pages it names
 * and the bundle is not one of them. A bundle occurrence is attributed to the
 * page its `<doc path="…">` section names and deferred only while that page
 * still produces the finding — so a page repointed without regenerating
 * `llms-full.txt` reports twice (the entry went stale for that page, and the
 * bundle carries a citation nothing defers) rather than going quiet, including
 * when a sibling page listed by the same entry still carries the old anchor.
 */
export function checkRepository(): Report {
  const documents = wikiDocuments()
  const read = (rel: string): string => readFileSync(join(REPO_ROOT, rel), 'utf8')
  const sources = new Map(documents.map(where => [where, read(where)]))

  const problems: Problem[] = [
    // Rule 7. First, because everything below is a statement about the
    // documents this list holds, and it is worth nothing if the list is short.
    ...checkCoverage(documents, sources.get(LLMS_FULL) ?? '')
      .map(({ where, detail }): Problem => ({ where, line: null, kind: 'coverage', detail })),
    ...documents.flatMap(where => checkLinksRead(sources.get(where)!, where)),
  ]
  const tracked: Report['tracked'] = []
  // Pairs, not a flag: an entry naming several pages is matched by each of them
  // separately, so one page's bundle copy is not kept alive by a sibling page
  // that still carries the same anchor (codex reported exactly that on #254).
  const matched = new Map<Tracked, Set<string>>()
  const files = new Map<string, { lines: string[] } | { detail: string }>()
  let resolved = 0

  const resolve = (where: string, sections: Section[] | null): void => {
    for (const anchor of parseAnchors(sources.get(where)!, where)) {
      resolved += 1
      if (!files.has(anchor.path)) {
        files.set(anchor.path, readCited(anchor.path))
      }
      const problem = checkAnchor(anchor, files.get(anchor.path)!)
      if (problem === null) {
        continue
      }
      // In the bundle an occurrence carries the bundle's own `where`, so the
      // page it has to be judged against is the one it was generated from. A
      // bundle line outside every `<doc>` section belongs to no page, and is
      // reported rather than deferred by whichever entry the anchor matches.
      const page = sections === null ? anchor.where : bundleOwner(sections, anchor.line)
      const entry = page === null
        ? undefined
        : TRACKED.find(known => defers(known, anchor, problem.kind, page))
      if (entry === undefined || page === null) {
        problems.push(problem)
        continue
      }
      if (sections === null) {
        matched.set(entry, (matched.get(entry) ?? new Set()).add(page))
      }
      else if (!(matched.get(entry)?.has(page) ?? false)) {
        // The page this text was generated from no longer produces the finding,
        // so the bundle was not regenerated after that page was repointed.
        problems.push(problem)
        continue
      }
      tracked.push({ entry, where, line: problem.line })
    }
  }

  // Pages first: `matched` is what the bundle pass consults, and only a page
  // occurrence may write to it. An entry kept alive by the bundle alone would
  // outlive the page citation the issue is actually about.
  for (const where of documents.filter(where => where !== LLMS_FULL)) {
    resolve(where, null)
  }
  if (sources.has(LLMS_FULL)) {
    resolve(LLMS_FULL, bundleSections(sources.get(LLMS_FULL)!))
  }

  return {
    problems,
    tracked,
    stale: TRACKED.flatMap(entry => entry.pages
      .filter(page => !(matched.get(entry)?.has(`wiki/${page}`) ?? false))
      .map(page => ({ entry, page: `wiki/${page}` }))),
    resolved,
  }
}

export function main(): number {
  const { problems, tracked, stale, resolved } = checkRepository()

  for (const { where, line, detail } of problems) {
    console.error(line === null ? `${where}: ${detail}` : `${where}:${line}: ${detail}`)
  }
  for (const { entry, page } of stale) {
    console.error(
      `scripts/check-wiki-source-anchors.ts: TRACKED names \`${entry.path}#L${entry.start}-L${entry.end}\` `
      + `(${entry.kind}, #${entry.issue}) on \`${page}\`, which produces no such finding any more — `
      + 'the anchor was repointed or removed, so drop that page from the entry, and the entry with '
      + 'its last page',
    )
  }

  if (problems.length > 0 || stale.length > 0) {
    console.error(
      `\nwiki source anchors: ${problems.length + stale.length} problem(s) across ${resolved} `
      + 'citation(s). Resolve each anchor against the file as it is now and repoint it — the range '
      + 'must start on the item its link text names. A finding only in `wiki/llms-full.txt` means '
      + 'the page was fixed and the bundle was not regenerated: `cd wiki && bun '
      + '.vitepress/gen-llms-full.mjs`.',
    )
    return 1
  }

  console.log(`wiki source anchors: ${resolved} citation(s) resolve against the files they cite`)

  // Listed by anchor rather than by occurrence: one stale anchor shows up once
  // per page that cites it and once more in the `llms-full.txt` bundle, and
  // forty entries read as forty pieces of work while ninety-eight read as
  // noise. The occurrence count is kept, because it is what a reader fixing one
  // has to go and edit.
  const occurrences = new Map<Tracked, number>()
  for (const { entry } of tracked) {
    occurrences.set(entry, (occurrences.get(entry) ?? 0) + 1)
  }
  if (occurrences.size > 0) {
    const byIssue = new Map<number, number>()
    for (const entry of occurrences.keys()) {
      byIssue.set(entry.issue, (byIssue.get(entry.issue) ?? 0) + 1)
    }
    const owed = [...byIssue].sort(([a], [b]) => a - b).map(([issue, count]) => `#${issue}: ${count}`)
    console.log(
      `${occurrences.size} known-stale anchor(s) left to their own issues — ${owed.join(', ')}. `
      + 'These are reported, not exempt: a new one fails.',
    )
    for (const [entry, count] of occurrences) {
      const cited = count === 1 ? '1 citation' : `${count} citations`
      console.log(
        `  #${entry.issue} ${entry.path}#L${entry.start}-L${entry.end} `
        + `(opens on a ${entry.kind === 'range' ? 'line past the end of the file' : entry.kind === 'blank' ? 'blank line' : 'closing delimiter'}, `
        + `${cited}) — ${entry.pages.join(', ')}`,
      )
    }
  }
  return 0
}

if (import.meta.main) {
  process.exit(main())
}
