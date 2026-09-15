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
 *    resolved count and unable to produce a finding. Review found three shapes
 *    that fell out this way, and a fourth will be written eventually; this rule
 *    is what makes any of them loud rather than the pattern being widened once
 *    per shape.
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
 * any other. What it cannot tell apart is a *new* citation that coincides with
 * a tracked one on the same page — same file, same range, same rule — which
 * reads as the tracked occurrence. Read the guarantee as "the rules above,
 * applied to every citation outside the ledger's own pages", and not as
 * anything about the drift those rules cannot see.
 *
 * `llms-full.txt` is scanned with the pages, for the reason
 * `check-wiki-io-claim.ts` scans it: it is generated
 * (`wiki/.vitepress/gen-llms-full.mjs`) and inlines every page, so a page
 * repointed without regenerating it leaves the stale anchor in the file LLM
 * readers actually consume.
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
  = /\[([^\]\n]{0,200})\]\(https:\/\/github\.com\/pleaseai\/honmoon\/blob\/([^/)]+)\/([^)?#\s]+)(?:\?[^)#\s]*)?(?:#L(\d+)(?:C\d+)?(?:-L(\d+)(?:C\d+)?)?)?\)/g

/**
 * A markdown link into this repository's blob tree, counted but not parsed.
 *
 * Deliberately just the `](` and the prefix: it is what {@link ANCHOR} has to
 * account for, so the two disagreeing is the signal rule 6 reports. It counts a
 * link written as markdown; a bare URL in prose is not a citation either
 * pattern reads, and is not counted as one.
 */
const BLOB_LINK = /\]\(https:\/\/github\.com\/pleaseai\/honmoon\/blob\//g

/** A line holding nothing but the end of the item above it. */
const BARE_DELIMITER = /^[)\]}]+[,;]?$/

/** Link text that spells its own line numbers, e.g. `lib.rs:57-152`. */
const TEXT_LINES = /:(\d+)(?:-(\d+))?$/

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
   * so its copy is deferred only while the entry still matches one of them —
   * which makes a page repointed without regenerating the bundle two findings
   * (a stale entry and an unread bundle citation) rather than none.
   */
  pages: string[]
}

export interface Report {
  problems: Problem[]
  tracked: { entry: Tracked, where: string, line: number }[]
  /** Entries that matched nothing — the anchor was fixed or removed. */
  stale: Tracked[]
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
export function defers(entry: Tracked, anchor: Anchor, kind: Kind): boolean {
  return entry.path === anchor.path
    && entry.start === anchor.start
    && entry.end === anchor.end
    && entry.kind === kind
    && entry.pages.some(page => `wiki/${page}` === anchor.where)
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
 * and the bundle is not one of them. A bundle occurrence is deferred only while
 * its entry still matches a page — so a page repointed without regenerating
 * `llms-full.txt` reports twice (the entry went stale, and the bundle carries a
 * citation nothing defers) rather than going quiet.
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
  const matched = new Set<Tracked>()
  const files = new Map<string, { lines: string[] } | { detail: string }>()
  let resolved = 0

  const resolve = (where: string, deferrable: boolean): void => {
    for (const anchor of parseAnchors(sources.get(where)!, where)) {
      resolved += 1
      if (!files.has(anchor.path)) {
        files.set(anchor.path, readCited(anchor.path))
      }
      const problem = checkAnchor(anchor, files.get(anchor.path)!)
      if (problem === null) {
        continue
      }
      const entry = deferrable
        ? TRACKED.find(known => defers(known, anchor, problem.kind))
        // In the bundle an occurrence carries the page's own `where`, so
        // `defers` can never match it. What defers it is that its entry is
        // still deferring the page this text was generated from.
        : [...matched].find(known =>
            known.path === anchor.path
            && known.start === anchor.start
            && known.end === anchor.end
            && known.kind === problem.kind)
      if (entry === undefined) {
        problems.push(problem)
      }
      else {
        if (deferrable) {
          matched.add(entry)
        }
        tracked.push({ entry, where, line: problem.line })
      }
    }
  }

  // Pages first: `matched` is what the bundle pass consults, and only a page
  // occurrence may write to it. An entry kept alive by the bundle alone would
  // outlive the page citation the issue is actually about.
  for (const where of documents.filter(where => where !== LLMS_FULL)) {
    resolve(where, true)
  }
  if (sources.has(LLMS_FULL)) {
    resolve(LLMS_FULL, false)
  }

  return {
    problems,
    tracked,
    stale: TRACKED.filter(entry => !matched.has(entry)),
    resolved,
  }
}

export function main(): number {
  const { problems, tracked, stale, resolved } = checkRepository()

  for (const { where, line, detail } of problems) {
    console.error(line === null ? `${where}: ${detail}` : `${where}:${line}: ${detail}`)
  }
  for (const entry of stale) {
    console.error(
      `scripts/check-wiki-source-anchors.ts: TRACKED names \`${entry.path}#L${entry.start}-L${entry.end}\` `
      + `(${entry.kind}, #${entry.issue}), which no citation in the wiki produces any more — `
      + 'the anchor was repointed or removed, so drop the entry',
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
