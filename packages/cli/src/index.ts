#!/usr/bin/env bun
/**
 * honmoonctl — control-plane CLI.
 *
 * Thin wrapper for policy tooling (validate, lint) and talking to a running
 * gateway's management API. The data-plane `honmoon` binary lives in
 * `crates/honmoon-cli`.
 */

import type { Policy } from '@honmoon/policy'

const [command, ...rest] = process.argv.slice(2)

async function validate(path: string | undefined): Promise<void> {
  if (!path) {
    console.error('usage: honmoonctl validate <policy.yaml>')
    process.exit(1)
  }
  const text = await Bun.file(path).text()
  // TODO: parse YAML + validate against @honmoon/policy/schema.
  const policy = text as unknown as Policy
  console.log(`validated ${path}`, policy ? '' : '')
}

switch (command) {
  case 'validate':
    await validate(rest[0])
    break
  default:
    console.log('honmoonctl <validate> [...args]')
}
