---
name: release
description: Prepare and publish a new release. Use when the user asks to release, cut a release, or publish a new version.
---

## Purpose

Release a new version of passless using the release script and CI pipeline.

## When to use

Use this skill when:
- The user asks to release a new version
- The user asks to cut a release or publish
- The user asks to tag a new version

## Prerequisites

Before releasing, verify:

1. **Working tree is clean** — no uncommitted changes
2. **You are on `master`** — releases only happen from master
3. **Local master is up to date with origin/master**
4. **No commits ahead of origin/master** (output of `git rev-list --count origin/master..HEAD` must be 0)
5. **Repository is not a shallow clone** — git-cliff needs full history for accurate changelogs

The release script handles shallow/latest-commit checkouts by fetching full history and tags before comparing against the remote default branch.

Check with:
```bash
git status --short
git rev-parse --abbrev-ref HEAD
git pull origin master
git rev-list --count origin/master..HEAD
git tag --sort=-creatordate | head -3
git log --oneline v<latest_tag>..HEAD
```

## Version Decision Guide

Use Semantic Versioning (MAJOR.MINOR.PATCH). Determine the bump type by analyzing commits since the last release.

### Major Version (X.0.0)

Bump MAJOR when:
- Breaking changes to CLI interface or arguments
- Breaking changes to configuration format
- Breaking changes to public APIs
- Commit message contains `BREAKING CHANGE:` or `!` (e.g., `feat!: ...`)

### Minor Version (0.X.0)

Bump MINOR when:
- New features added (`feat:` commits)
- New CLI commands or flags
- New configuration options
- Backward-compatible enhancements

### Patch Version (0.0.X)

Bump PATCH when:
- Bug fixes (`fix:` commits)
- Documentation updates (`docs:` commits)
- Internal refactoring (`refactor:` commits)
- Dependency updates (`chore(deps):` commits)

### Decision Process

1. Run: `git log v<CURRENT_VERSION>..HEAD --oneline`
2. Check commit messages for:
   - `!` or `BREAKING CHANGE:` -> MAJOR
   - `feat:` -> MINOR
   - `fix:`, `docs:`, `refactor:`, etc. -> PATCH
3. If multiple types, use the highest precedence (MAJOR > MINOR > PATCH)

## Release Process

### Step 1: Verify Clean State

Ensure you're on master with no uncommitted changes, up to date with origin, and no commits ahead:

```bash
git checkout master
git pull origin master
git status  # Should show "nothing to commit, working tree clean"
```

Verify no commits ahead of origin/master:

```bash
git rev-list --count origin/master..HEAD  # Should output 0
```

**Unshallow check** — shallow clones produce incomplete changelogs:

```bash
git rev-parse --is-shallow-repository
```

If this outputs `true`, unshallow the repo before proceeding:

```bash
git fetch --unshallow origin
git fetch --tags origin
```

Alternatively, run `.ci/release.sh`; it performs the shallow-clone and tag fetch checks before preparing the release.

### Step 2: Determine Version

1. Get current version:
   ```bash
   grep '^version =' Cargo.toml | head -1
   ```

2. Review commits since last release:
   ```bash
   git log v<CURRENT_VERSION>..HEAD --oneline
   ```

3. Decide on MAJOR, MINOR, or PATCH bump based on the Version Decision Guide above.

### Step 3: Create Release Branch

```bash
git checkout -b release/v<NEW_VERSION>
```

### Step 4: Update Version

Edit `Cargo.toml` and update the version in the `[workspace.package]` section:

```toml
version = "<NEW_VERSION>"
```

### Step 5: Update Dependencies

```bash
make update-version
```

This updates version references in workspace Cargo.toml files and runs `cargo update --workspace`.

### Step 6: Update Changelog

```bash
make update-changelog
```

This runs: `git cliff -t v<VERSION> -u -p CHANGELOG.md`

### Step 7: Commit Changes

```bash
git add .
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
git commit -m "release: Version $VERSION"
```

### Step 8: Push Branch and Create PR

```bash
git push -u origin release/v<NEW_VERSION>
```

Create a pull request to merge into master.

### Step 9: After Merge

After the PR is merged to master, tagging and releasing is done **automatically** by CI:

1. `auto-tag.yaml` reads the new version from `CHANGELOG.md`
2. Creates a signed GPG tag `v<VERSION>`
3. Pushes the tag to GitHub

The tag then triggers:
- `rust.yml`: Builds, tests, publishes to crates.io, creates GitHub Release
- `aur-publish.yml`: Publishes AUR packages (`passless` and `passless-bin`)

Monitor with:
```bash
gh run list --limit 5
```

**Note:** Do not manually create tags — CI handles this automatically.

## What NOT to Do

| Mistake | Why it's wrong | Fix |
|---------|---------------|-----|
| Manually editing CHANGELOG.md | git-cliff generates it from conventional commits | Use `make update-changelog` |
| Creating git tags manually | `auto-tag.yaml` creates signed tags automatically | Just push to master |
| Releasing from a feature branch | Changelog generation needs master commit IDs | Checkout master first |
| Releasing with dirty working tree | Script will fail or produce incomplete release | Commit or stash changes first |
| Skipping the unshallow check | Shallow clones produce incomplete changelogs | Always check and unshallow if needed |
| Forgetting `make update-version` after Cargo.toml edit | Version won't propagate to workspace members | Always run `make update-version` |
| Using `--amend` on a commit | May amend the wrong parent commit after hook failures | Just commit again normally |

## Troubleshooting

### "There are commits ahead of origin/master"
Merge or push them first before starting the release.

### Shallow clone detected
```bash
git fetch --unshallow origin
git fetch --tags origin
```

### git-cliff not installed
```bash
cargo install git-cliff
```

### Auto-tag workflow didn't trigger
Ensure:
- The CHANGELOG.md has a new version entry as the first `## [v...]` heading
- The tag doesn't already exist: `git tag -l | grep <version>`
- The `PAT` and `GPG_PRIVATE_KEY` secrets are configured in GitHub

### Commit failed due to pre-commit hooks
Do NOT use `--amend`. Simply stage the changes and commit again:
```bash
git add .
git commit -m "release: Version <VERSION>"
```

## Key Files

| File | Role |
|------|------|
| `Cargo.toml` | Workspace version (single source of truth) |
| `cliff.toml` | git-cliff configuration for changelog generation |
| `CHANGELOG.md` | Generated changelog (auto-tag reads version from here) |
| `.github/workflows/auto-tag.yaml` | Creates signed GPG tag on push to master |
| `.github/workflows/rust.yml` | Builds, tests, publishes to crates.io and GitHub on tag |
| `.github/workflows/aur-publish.yml` | Publishes AUR packages on tag |
| `Makefile` | `update-version` and `update-changelog` targets |
| `.ci/release.sh` | Full release script |

## Checklist

- [ ] On master branch, clean working tree
- [ ] Pulled latest from origin/master
- [ ] No commits ahead of origin/master
- [ ] Repository is not a shallow clone (or has been unshallowed)
- [ ] Determined version bump type (MAJOR/MINOR/PATCH)
- [ ] Created release branch `release/v<VERSION>`
- [ ] Updated version in `Cargo.toml`
- [ ] Ran `make update-version`
- [ ] Ran `make update-changelog`
- [ ] Committed with message `release: Version <VERSION>`
- [ ] Pushed and created PR
- [ ] After merge: CI automatically creates tag and release

## Quick Reference

| Step | Command |
|------|---------|
| Check current version | `grep '^version =' Cargo.toml \| head -1` |
| View recent commits | `git log v<CUR>..HEAD --oneline` |
| Check commits ahead | `git rev-list --count origin/master..HEAD` |
| Check shallow clone | `git rev-parse --is-shallow-repository` |
| Unshallow repo | `git fetch --unshallow origin && git fetch --tags origin` |
| Update version refs | `make update-version` |
| Update changelog | `make update-changelog` |
| Commit | `git commit -m "release: Version <VER>"` |
| Monitor CI | `gh run list --limit 5` |
| Run release script | `.ci/release.sh` |
