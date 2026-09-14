import { describe, expect, test } from 'bun:test'
import {
  checkConfig,
  checkRepository,
  checkWorkflow,
  PUBLISH_MARKERS,
  UPLOAD_MARKER,
} from './check-release-draft'

/** The root package as this repository configures it, reduced to what is checked. */
const CONFIG = {
  packages: {
    '.': {
      'release-type': 'simple',
      'draft': true,
      'force-tag-creation': true,
    },
  },
}

/** The `release` job as `release.yml` runs it, reduced to what is checked. */
const WORKFLOW = {
  jobs: {
    release: {
      steps: [
        { uses: 'actions/checkout@sha' },
        { name: 'Combine checksums', run: 'shasum -a 256 -c SHA256SUMS' },
        { name: 'Upload binaries', run: `${UPLOAD_MARKER} "$TAG" --clobber artifacts/*.tar.gz` },
        { name: 'Publish the Release', run: PUBLISH_MARKERS.join(' "$TAG" ') },
      ],
    },
  },
}

function details(problems: { detail: string }[]): string[] {
  return problems.map(problem => problem.detail)
}

describe('checkConfig', () => {
  test('the config this repository ships passes', () => {
    expect(checkConfig(CONFIG)).toEqual([])
  })

  test('a Release that is not drafted is reported — it would publish before any binary exists', () => {
    const published = structuredClone(CONFIG)
    // @ts-expect-error — removing a required setting is the regression under test.
    delete published.packages['.'].draft
    expect(details(checkConfig(published))).toEqual([
      expect.stringContaining('`packages["."].draft` is not `true`'),
    ])
  })

  test('drafting without force-tag-creation is reported — the tag ref would never be pushed', () => {
    const noTag = structuredClone(CONFIG)
    // @ts-expect-error — the coupling is the point: `draft` alone breaks every checkout.
    delete noTag.packages['.']['force-tag-creation']
    expect(details(checkConfig(noTag))).toEqual([
      expect.stringContaining('`packages["."].force-tag-creation` is not `true`'),
    ])
  })

  test('the settings are read from the root package, not from the top level', () => {
    // release-please honours both places; this repository uses one, and a
    // setting that drifted to the other has to read as missing rather than pass.
    const topLevel = { 'packages': { '.': {} }, 'draft': true, 'force-tag-creation': true }
    expect(checkConfig(topLevel)).toHaveLength(2)
  })

  test('a config with no root package is reported rather than passing vacuously', () => {
    expect(details(checkConfig({ packages: {} }))).toEqual([
      expect.stringContaining('no `packages["."]` object'),
    ])
  })
})

describe('checkWorkflow', () => {
  test('the release job this repository ships passes', () => {
    expect(checkWorkflow(WORKFLOW)).toEqual([])
  })

  test('a release job that never publishes is reported — the draft would stay invisible', () => {
    const noPublish = structuredClone(WORKFLOW)
    noPublish.jobs.release.steps = WORKFLOW.jobs.release.steps.slice(0, -1)
    expect(details(checkWorkflow(noPublish))).toEqual([
      expect.stringContaining('no step in `release` runs'),
    ])
  })

  test('publishing before the upload is reported — that is the window #230 closed', () => {
    const swapped = structuredClone(WORKFLOW)
    const steps = swapped.jobs.release.steps
    ;[steps[2], steps[3]] = [steps[3]!, steps[2]!]
    // Both halves of the ordering fire: the upload now trails the publish, and
    // the publish is no longer last.
    expect(details(checkWorkflow(swapped))).toEqual([
      expect.stringContaining('after the publish at step'),
      expect.stringContaining('it has to be the last one'),
    ])
  })

  test('a step appended after the publish is reported — it would run against a visible Release', () => {
    const appended = structuredClone(WORKFLOW)
    appended.jobs.release.steps.push({ name: 'Announce', run: 'echo shipped' })
    expect(details(checkWorkflow(appended))).toEqual([
      expect.stringContaining('it has to be the last one'),
    ])
  })

  test('a workflow with no release job is reported rather than passing vacuously', () => {
    expect(details(checkWorkflow({ jobs: { build: {} } }))).toEqual([
      expect.stringContaining('no `release` job with a `steps` list'),
    ])
  })

  // The publish step is located by what a step *runs*. These two pin that: a
  // step that only mentions publishing must not be mistaken for the one that
  // does it, in either direction — standing in for the real step (which moves
  // every reported index) or standing in for a real step that is gone.
  test('an earlier step that merely echoes the flag is not mistaken for the publish', () => {
    const decoyed = structuredClone(WORKFLOW)
    decoyed.jobs.release.steps.splice(1, 0, {
      name: 'Announce',
      run: 'echo "the last step will pass --draft=false"',
    })
    expect(checkWorkflow(decoyed)).toEqual([])
  })

  test('a commented-out publish does not satisfy the check', () => {
    const commented = structuredClone(WORKFLOW)
    const steps = commented.jobs.release.steps
    steps[steps.length - 1] = {
      name: 'Publish the Release',
      run: `# TODO: restore ${PUBLISH_MARKERS.join(' "$TAG" ')}\necho skipped`,
    }
    expect(details(checkWorkflow(commented))).toEqual([
      expect.stringContaining('nothing publishes'),
    ])
  })
})

describe('checkRepository', () => {
  // The end-to-end assertion, over the real files rather than the fixtures
  // above: a Release this repository cuts is not visible until its binaries
  // are on it.
  test('the files this repository ships close the binary-less window', () => {
    expect(checkRepository()).toEqual([])
  })
})
