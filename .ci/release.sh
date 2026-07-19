#!/bin/bash
set -euo pipefail

ensure_full_history() {
    if git rev-parse --is-shallow-repository 2>/dev/null | grep -q "true"; then
        echo "Shallow clone detected. Fetching full history and tags..."
        git fetch --unshallow --quiet
    fi
    if [ -z "$(git tag -l)" ]; then
        echo "No tags found. Fetching tags..."
        git fetch --tags --quiet
    fi
}

ensure_clean_state() {
    if ! git diff --quiet || ! git diff --cached --quiet; then
        echo "Working tree is not clean. Commit or stash changes first."
        exit 1
    fi

    REMOTE="origin"

    if ! git remote | grep -q "^$REMOTE$"; then
        echo "Remote '$REMOTE' does not exist. Please configure git remote."
        exit 1
    fi

    git fetch "$REMOTE" --quiet

    DEFAULT_BRANCH=$(git symbolic-ref "refs/remotes/$REMOTE/HEAD" 2>/dev/null | sed 's@^refs/remotes/[^/]*/@@' || git remote show "$REMOTE" 2>/dev/null | grep "HEAD branch" | sed 's/.*: //')

    if [ -z "$DEFAULT_BRANCH" ]; then
        echo "Could not determine default branch from remote '$REMOTE'."
        echo "Please ensure git remote is properly configured."
        exit 1
    fi

    REMOTE_BRANCH="refs/remotes/$REMOTE/$DEFAULT_BRANCH"
    if ! git show-ref --quiet "$REMOTE_BRANCH"; then
        echo "Branch '$DEFAULT_BRANCH' does not exist in remote '$REMOTE'."
        echo "Please ensure the remote has a default branch."
        exit 1
    fi

    LOCAL_BRANCH=$(git rev-parse --abbrev-ref HEAD)
    if [ "$LOCAL_BRANCH" = "$DEFAULT_BRANCH" ]; then
        git pull "$REMOTE" "$DEFAULT_BRANCH" --quiet
    else
        COMMIT_COUNT=$(git rev-list --count "$REMOTE_BRANCH"..HEAD 2>/dev/null || echo 1)
        if [ "$COMMIT_COUNT" -ne 0 ]; then
            echo "There are $COMMIT_COUNT commits in '$LOCAL_BRANCH' branch that are not in '$REMOTE/$DEFAULT_BRANCH'."
            echo "Please merge them first. CHANGELOG template needs the latest commit from '$DEFAULT_BRANCH'."
            exit 1
        fi
    fi
}

echo "=== Checking repository state ==="
ensure_full_history
ensure_clean_state

echo ""
echo "=== Recent commits since last release ==="
LATEST_TAG=$(git tag --sort=-creatordate | head -1)
if [ -n "$LATEST_TAG" ]; then
    git log "$LATEST_TAG"..HEAD --oneline
else
    git log --oneline -10
fi

echo ""
echo "=== Bumping version ==="
vim ./Cargo.toml

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' ./Cargo.toml | head -n1)
echo "New version: $VERSION"

echo ""
echo "=== Updating dependencies ==="
make update-version

echo ""
echo "=== Updating changelog ==="
make update-changelog

echo ""
echo "=== Committing release ==="
git add .
git commit -m "release: Version $VERSION"

echo ""
echo "=== Creating release branch and pushing ==="
git checkout -b "release/v$VERSION"
git push -u origin "release/v$VERSION"

echo ""
echo "Release v$VERSION prepared successfully."
echo "Create a PR to merge release/v$VERSION into master."
echo "After merge, tag and GitHub release are created automatically."
