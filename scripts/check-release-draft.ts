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

/** What the publish step's `run:` must contain for this check to find it. */
export const PUBLISH_MARKER = '--draft=false'

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

  const publishAt = runs.findIndex(run => run.includes(PUBLISH_MARKER))
  if (publishAt === -1) {
    return [{
      where: WORKFLOW_PATH,
      detail: `no step in \`${RELEASE_JOB}\` runs \`${PUBLISH_MARKER}\` — nothing publishes the draft, `
        + 'so a release would never become visible (#230)',
    }]
  }

  const problems: Problem[] = []
  const uploadAt = runs.findIndex(run => run.includes(UPLOAD_MARKER))
  if (uploadAt === -1) {
    problems.push({
      where: WORKFLOW_PATH,
      detail: `no step in \`${RELEASE_JOB}\` runs \`${UPLOAD_MARKER}\` — the publish step has nothing to publish`,
    })
  }
  else if (uploadAt > publishAt) {
    problems.push({
      where: WORKFLOW_PATH,
      detail: `\`${UPLOAD_MARKER}\` runs at step ${uploadAt + 1}, after the publish at step ${publishAt + 1}`
        + ' — that publishes a Release with no binaries on it, which is the window #230 closed',
    })
  }

  if (publishAt !== runs.length - 1) {
    problems.push({
      where: WORKFLOW_PATH,
      detail: `the publish is step ${publishAt + 1} of ${runs.length} in \`${RELEASE_JOB}\` — it has to be `
        + 'the last one, because every step after it runs against a Release users can already see',
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
