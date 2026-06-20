# Project Workflow

> Development workflow conventions for Honmoon. Referenced by `/please:implement`.

## Guiding Principles

1. **The Plan is the Source of Truth**: All work is tracked in the track's `plan.md`
2. **The Tech Stack is Deliberate**: Changes to the tech stack must be documented in `tech-stack.md` before implementation
3. **Test-Driven Development**: Write tests before implementing functionality
4. **High Code Coverage**: Aim for >80% code coverage for new code
5. **Non-Interactive & CI-Aware**: Prefer non-interactive commands. Use `CI=true` for watch-mode tools

## Task Workflow

All tasks follow a strict lifecycle within `/please:implement`:

### Standard Task Lifecycle

1. **Select Task**: Choose the next available task from `plan.md`
2. **Mark In Progress**: Update task status from `[ ]` to `[~]`
3. **Write Failing Tests (Red Phase)**: Define expected behavior, confirm tests fail
4. **Implement to Pass Tests (Green Phase)**: Minimum code to pass, confirm suite green
5. **Refactor (Optional)**: Improve clarity / remove duplication, rerun tests
6. **Verify Coverage**: Target >80% for new code
7. **Document Deviations**: If implementation differs from tech stack, update `tech-stack.md` first
8. **Commit**: Conventional commit message (one commit per task)
9. **Update Progress**: Mark the task complete in `## Progress` with a timestamp

### Phase Completion Protocol

1. **Verify Test Coverage** of all files changed in the phase
2. **Run Full Test Suite**, debug failures (max 2 fix attempts)
3. **Manual Verification Plan** for the user
4. **User Confirmation**: wait for explicit approval before proceeding
5. **Create Checkpoint**: commit `chore(checkpoint): complete phase {name}`.
   Stacked PR is **enabled** (`workflow.stacked_pr.enabled=true`), so `/please:implement`
   also runs `gt submit --stack` here to refresh all PRs in the stack.
6. **Update Plan**: mark the phase complete in `plan.md`

## Quality Gates

Before marking any task complete:

- [ ] All tests pass
- [ ] Code coverage meets requirements (>80%)
- [ ] Code follows project style guidelines (`cargo fmt`, dashboard `eslint`)
- [ ] No linting / static-analysis errors (`cargo clippy`, `tsc --noEmit`)
- [ ] No security vulnerabilities introduced
- [ ] Documentation updated if needed

## Development Commands

### Setup

```bash
bun install                 # JS workspace (packages/*, apps/*)
cargo fetch                 # Rust deps
```

### Daily Development

```bash
cargo run -p honmoon-cli -- --help   # data-plane CLI
bun run dashboard:dev                 # dashboard dev server (HMR)
bun --filter @honmoon/api dev         # control-plane API (watch)
```

### Testing

```bash
cargo test --workspace               # Rust tests
bun test                             # TS tests
```

### Before Committing

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
bun run lint                         # tsc / eslint across workspace
cargo test --workspace && bun test
```

## Commit Guidelines

Follow Conventional Commits. See `Skill("standards:commit-convention")`.

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.

## Definition of Done

1. Code implemented to specification
2. Tests written and passing (Rust + TS as applicable)
3. Coverage meets requirements
4. All configured checks pass (`fmt`, `clippy`, `tsc`, `eslint`)
5. Progress updated in `plan.md`
6. Changes committed with a proper message
