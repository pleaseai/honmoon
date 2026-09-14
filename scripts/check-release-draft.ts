/**
 * Check that the release pipeline publishes a Release only once its binaries are on it.
 *
 * release-please tags `vX.Y.Z` and creates the Release, and `release.yml` builds
 * the three binaries afterwards. Publishing at tag time therefore put a stable
 * Release carrying a CHANGELOG and no assets at `/releases/latest` for the
 * length of three native builds — and left it there indefinitely if a `build`
 * runner failed (#230). The fix is to create the Release as a draft and flip the
 * draft off as the very last thing the pipeline does.
 *
 * That fix is three settings spread across two files, and each one silently
 * undoes it on its own:
 *
 *  - `draft: true` is what closes the window. Without it nothing else here
 *    matters.
 *  - `force-tag-creation: true` is what keeps the rest of the pipeline working
 *    once the Release is a draft. GitHub does not create the tag ref for a draft
 *    Release, and release-please pushes `refs/tags/<tag>` itself only under this
 *    option, so without it every `refs/tags/${{ inputs.tag }}` checkout in
 *    `release.yml` resolves nothing. It is inert while `draft` is off, which is
 *    exactly why it is easy to drop.
 *  - The publish step has to be **last**. A step added after it runs against a
 *    Release users can already see, which is the window reopened by one line in
 *    the wrong place.
 *
 * None of the three can be checked by running anything: the pipeline they
 * describe executes once per release, in an environment CI does not have, and
 * its failure is discovered by users rather than by a red build. So they are
 * asserted here, against the files themselves.
 *
 * What this deliberately does **not** assert is that `gh` resolves a draft
 * Release by tag name. `gh release view/edit/upload` all resolve a tag through
 * `shared.FetchRelease`, which races `GET /releases/tags/{tag}` — which does not
 * return drafts — against a GraphQL `repository.release(tagName:)` lookup that
 * does. That is a property of the `gh` on the runner image, not of this
 * repository, so it is guarded where it runs: the publish step reads the draft
 * back with `gh release view` before editing it, and fails the job by name if a
 * future image ever stops resolving it.
 *
 * Usage:
 *   bun scripts/check-release-draft.ts
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

/** Repository root, resolved from this file rather than the working directory. */
export const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url))

export const CONFIG_PATH = 'release-please-config.json'
export const WORKFLOW_PATH = '.github/workflows/release.yml'

/** The job in `release.yml` that owns the upload and the publish. */
export const RELEASE_JOB = 'release'

/**
 * What the publish step's `run:` must contain for this check to find it — both
 * of them, in the same step.
 *
 * Two markers rather than one because `--draft=false` alone is a string a
 * diagnostic `echo` can hold, and this file's own steps are written with long
 * `#` commentary around the command. A step that merely *mentions* publishing
 * would then be mistaken for the step that does it, which moves `publishAt` and
 * makes this checker report on the wrong line — or, if the decoy sits last and
 * the real step is gone, report nothing at all.
 */
export const PUBLISH_MARKERS = ['gh release edit', '--draft=false']

/** What the upload step's `run:` must contain for this check to find it. */
export const UPLOAD_MARKER = 'gh release upload'

export interface Problem {
  /** The file the problem is in, for the reported line. */
  where: string
  detail: string
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * The root package's releaser options.
 *
 * release-please reads both of these at the top level too, but this repository
 * configures the root package under `packages["."]` and a split between the two
 * places would be its own trap — so only that one object is read, and a setting
 * moved to the top level reads here as a setting that is missing.
 */
function rootPackage(config: unknown): Record<string, unknown> | undefined {
  if (!isRecord(config) || !isRecord(config.packages)) {
    return undefined
  }
  const root = config.packages['.']
  return isRecord(root) ? root : undefined
}

export function checkConfig(config: unknown): Problem[] {
  const root = rootPackage(config)
  if (!root) {
    return [{
      where: CONFIG_PATH,
      detail: 'no `packages["."]` object — the root package is where this repository configures the release',
    }]
  }

  const problems: Problem[] = []
  if (root.draft !== true) {
    problems.push({
      where: CONFIG_PATH,
      detail: '`packages["."].draft` is not `true` — release-please would publish the Release '
        + 'at tag time, before release.yml has built any binary (#230)',
    })
  }
  if (root['force-tag-creation'] !== true) {
    problems.push({
      where: CONFIG_PATH,
      detail: '`packages["."].force-tag-creation` is not `true` — GitHub creates no tag ref for '
        + 'a draft Release, so every `refs/tags/` checkout in release.yml would resolve nothing',
    })
  }
  return problems
}

/**
 * One `run:` script with its whole-line `#` comments removed.
 *
 * The markers have to be matched against what the shell will execute. These
 * workflows carry paragraphs of commentary inside `run:` blocks — the publish
 * step's own comment discusses the command it guards — so matching the raw text
 * would let prose about a command stand in for the command.
 */
function commands(run: string): string {
  return run
    .split('\n')
    .filter(line => !/^\s*#/.test(line))
    .join('\n')
}

/**
 * Where a command sits: the index of its step, then its offset within that
 * step's script.
 *
 * A step index alone cannot order two commands that share one `run:` block, and
 * nothing stops the upload and the publish from being written as one step. Two
 * commands at the same index compared by index alone read as simultaneous, so a
 * block that publishes *before* it uploads would satisfy an index-only check.
 */
interface Position {
  step: number
  offset: number
}

/**
 * The first step whose script carries every one of `markers`, and where in that
 * script the command starts — located by `markers[0]`, which is the command word
 * rather than one of its flags.
 */
function findCommand(runs: string[], markers: string[]): Position | undefined {
  for (const [step, run] of runs.entries()) {
    const script = commands(run)
    if (markers.every(marker => script.includes(marker))) {
      return { step, offset: script.indexOf(markers[0]!) }
    }
  }
  return undefined
}

/** Whether `a` runs before `b` — by step, then within a shared step. */
function runsBefore(a: Position, b: Position): boolean {
  return a.step === b.step ? a.offset < b.offset : a.step < b.step
}

/** The `run:` scripts of one job's steps, in order. */
function stepRuns(workflow: unknown, job: string): string[] | undefined {
  if (!isRecord(workflow) || !isRecord(workflow.jobs)) {
    return undefined
  }
  const found = workflow.jobs[job]
  if (!isRecord(found) || !Array.isArray(found.steps)) {
    return undefined
  }
  return found.steps.map(step => (isRecord(step) && typeof step.run === 'string' ? step.run : ''))
}

export function checkWorkflow(workflow: unknown): Problem[] {
  const runs = stepRuns(workflow, RELEASE_JOB)
  if (!runs) {
    return [{
      where: WORKFLOW_PATH,
      detail: `no \`${RELEASE_JOB}\` job with a \`steps\` list — this is the job that uploads the binaries and publishes the Release`,
    }]
  }

  const publish = findCommand(runs, PUBLISH_MARKERS)
  if (!publish) {
    return [{
      where: WORKFLOW_PATH,
      detail: `no step in \`${RELEASE_JOB}\` runs \`${PUBLISH_MARKERS.join('… ')}\` — nothing publishes `
        + 'the draft, so a release would never become visible (#230)',
    }]
  }

  const problems: Problem[] = []
  const upload = findCommand(runs, [UPLOAD_MARKER])
  if (!upload) {
    problems.push({
      where: WORKFLOW_PATH,
      detail: `no step in \`${RELEASE_JOB}\` runs \`${UPLOAD_MARKER}\` — the publish step has nothing to publish`,
    })
  }
  else if (!runsBefore(upload, publish)) {
    const where = upload.step === publish.step
      ? `later in step ${publish.step + 1} than the publish does`
      : `at step ${upload.step + 1}, after the publish at step ${publish.step + 1}`
    problems.push({
      where: WORKFLOW_PATH,
      detail: `\`${UPLOAD_MARKER}\` runs ${where} — that publishes a Release with no `
        + 'binaries on it, which is the window #230 closed',
    })
  }

  if (publish.step !== runs.length - 1) {
    problems.push({
      where: WORKFLOW_PATH,
      detail: `the publish is step ${publish.step + 1} of ${runs.length} in \`${RELEASE_JOB}\` — it has to `
        + 'be the last one, because every step after it runs against a Release users can already see',
    })
  }
  return problems
}

export function checkRepository(): Problem[] {
  const config: unknown = JSON.parse(readFileSync(join(REPO_ROOT, CONFIG_PATH), 'utf8'))
  const workflow: unknown = Bun.YAML.parse(readFileSync(join(REPO_ROOT, WORKFLOW_PATH), 'utf8'))
  return [...checkConfig(config), ...checkWorkflow(workflow)]
}

export function main(): number {
  const problems = checkRepository()

  if (problems.length > 0) {
    for (const { where, detail } of problems) {
      console.error(`${where}: ${detail}`)
    }
    console.error(
      `\nrelease draft: ${problems.length} problem(s). A GitHub Release must not be visible `
      + 'before its binaries are on it — see docs/releasing.md.',
    )
    return 1
  }

  console.log(
    `release draft: ${CONFIG_PATH} drafts the Release and creates its tag, and `
    + `${WORKFLOW_PATH} publishes it only after the upload`,
  )
  return 0
}

if (import.meta.main) {
  process.exit(main())
}
