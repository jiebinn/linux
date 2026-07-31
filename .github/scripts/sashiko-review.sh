#!/usr/bin/env bash
set -euo pipefail

# Inputs (from env):
#   REPO_PATH       — kernel checkout (PR head)
#   SASHIKO_PATH    — sashiko checkout (with built binary in target/release/review)
#   BASE_SHA        — PR base commit
#   HEAD_SHA        — PR head commit
#   MAX_PATCHES     — abort if PR has more commits than this
#   MODEL           — bedrock model id (e.g. us.anthropic.claude-sonnet-4-6)
#   OUTPUT_DIR      — where to write per-patch review JSON + combined markdown

: "${REPO_PATH:?}" "${SASHIKO_PATH:?}" "${BASE_SHA:?}" "${HEAD_SHA:?}"
: "${MAX_PATCHES:=5}" "${MODEL:=us.anthropic.claude-sonnet-4-6}"
: "${OUTPUT_DIR:=$PWD/sashiko-out}"

mkdir -p "$OUTPUT_DIR"

mapfile -t COMMITS < <(git -C "$REPO_PATH" log --reverse --format='%H' "$BASE_SHA..$HEAD_SHA")
N=${#COMMITS[@]}

if (( N == 0 )); then
    echo "No commits in $BASE_SHA..$HEAD_SHA — nothing to review."
    echo "SASHIKO_SKIP=1" >> "${GITHUB_ENV:-/dev/null}"
    exit 0
fi

# Honor an optional partial-review directive (review-num-commits /
# review-git-range) from the PR body or a workflow input. This may narrow
# COMMITS to a subset, or skip the review entirely on an invalid directive.
TOTAL_PR_COMMITS=$N
# shellcheck source=select-commits.sh
source "$(dirname "$0")/select-commits.sh"
SKIP_PREFIX=SASHIKO
select_commits "${COMMITS[@]}"
COMMITS=("${SELECTED_COMMITS[@]}")
N=${#COMMITS[@]}

if (( N > MAX_PATCHES )); then
    {
        printf '**Sashiko review skipped:** this PR has %d commits, exceeding the limit of %d.\n\n' "$N" "$MAX_PATCHES"
        printf 'Large series take a long time and consume significant model budget. \n'
        printf '**Check that your PR base is correct.** A common cause of an inflated commit count is branching from the wrong base, which pulls in unrelated upstream commits.\n'
        printf 'If your commits are based on another base use one of the following options to review a subset of the commits: \n\n'
        printf '    review-num-commits: <n>          review only the last <n> commits\n'
        printf '    review-git-range:   <sha>..<sha> review only that range (must be subset of PR)\n\n'
    } > "$OUTPUT_DIR/comment.md"
    echo "SASHIKO_TOO_MANY=1" >> "${GITHUB_ENV:-/dev/null}"
    exit 0
fi

REVIEW_BIN="$SASHIKO_PATH/target/release/review"
PROMPTS_DIR="$SASHIKO_PATH/third_party/prompts/kernel"

# Disable background gc/maintenance on the shared (cached) repo. Auto-gc can
# fire mid-run and hold the repo lock, which has wedged `git worktree add` /
# `git reset --hard` for hours on the kernel-sized repo.
git -C "$REPO_PATH" config gc.auto 0 || true
git -C "$REPO_PATH" config maintenance.auto false || true
git -C "$REPO_PATH" worktree prune 2>/dev/null || true

# Create a single shared worktree reused across all commits instead of letting
# the review binary create a fresh worktree per commit. This collapses N
# (git worktree add + git reset --hard) cycles into one add plus cheap
# incremental resets between consecutive commits in the series, reducing both
# runtime and exposure to git worktree-creation hangs on the shared repo.
WT_PARENT="$(mktemp -d)"
WT="$WT_PARENT/wt"
cleanup_wt() {
    git -C "$REPO_PATH" worktree remove -f "$WT" 2>/dev/null || true
    git -C "$REPO_PATH" worktree prune 2>/dev/null || true
    rm -rf "$WT_PARENT"
}
trap cleanup_wt EXIT
git -C "$REPO_PATH" -c safe.bareRepository=all \
    worktree add --no-checkout --detach "$WT" "$BASE_SHA"

echo "Reviewing $N commit(s) with $MODEL..."

# Record the total patch count so an always()-guarded workflow step can tell,
# even if this script is killed mid-run (timeout), how many of the N patches
# were actually reviewed and annotate the partial comment accordingly.
echo "$N" > "$OUTPUT_DIR/total-patches"

{
    printf '# Sashiko review\n\n'
    printf 'Model: `%s`  \n' "$MODEL"
    printf 'Base: `%s`  \n' "$BASE_SHA"
    printf 'Head: `%s`  \n' "$HEAD_SHA"
    if [[ -n "${REVIEW_SELECTION:-}" ]]; then
        printf 'Partial review: %s — %d of %d commits  \n' \
            "$REVIEW_SELECTION" "$N" "$TOTAL_PR_COMMITS"
    fi
    printf '\n'
} > "$OUTPUT_DIR/comment.md"

FAIL_COUNT=0
for i in "${!COMMITS[@]}"; do
    SHA="${COMMITS[$i]}"
    IDX=$((i + 1))
    SUBJ=$(git -C "$REPO_PATH" log -1 --format='%s' "$SHA")
    AUTH=$(git -C "$REPO_PATH" log -1 --format='%an <%ae>' "$SHA")
    DATE=$(git -C "$REPO_PATH" log -1 --format='%at' "$SHA")
    DIFF=$(git -C "$REPO_PATH" format-patch -1 --stdout "$SHA")

    INPUT="$OUTPUT_DIR/input-$IDX.json"
    OUTPUT="$OUTPUT_DIR/output-$IDX.json"

    jq -cn \
        --arg subj "$SUBJ" --arg auth "$AUTH" --argjson date "$DATE" \
        --arg diff "$DIFF" --arg sha "$SHA" --argjson id "$IDX" \
        '{id: $id, subject: $subj, patches: [
            {index: 1, diff: $diff, subject: $subj, author: $auth, date: $date, commit_id: $sha}
        ]}' > "$INPUT"

    echo "=== [$IDX/$N] $SHA $SUBJ ==="

    # Baseline is the parent of this commit, so sashiko's worktree starts there
    # and the commit checkout reproduces the tree state at $SHA.
    if ( cd "$SASHIKO_PATH" && ./target/release/review \
            --baseline "${SHA}^" \
            --review-patch-index 1 \
            --reuse-worktree "$WT" \
            --prompts "$PROMPTS_DIR" \
            < "$INPUT" > "$OUTPUT" ); then
        INLINE=$(jq -r '.inline_review // ""' "$OUTPUT")
        ERR=$(jq -r '.error // ""' "$OUTPUT")

        # Determine failure status in the parent shell — the printf block below
        # runs in a pipe subshell, so incrementing FAIL_COUNT inside it would be
        # lost.
        if [[ ( -n "$ERR" && "$ERR" != "null" ) || -z "$INLINE" || "$INLINE" == "null" ]]; then
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi

        # tee each patch's block to stdout as well as comment.md, so completed
        # reviews are visible in the live workflow log even if the job is killed
        # (timeout/OOM) before the final "post comment" step runs.
        {
            printf '\n---\n\n## Patch %d/%d — `%s`\n\n' "$IDX" "$N" "${SHA:0:12}"
            printf '**%s**\n\n' "$SUBJ"
            if [[ -n "$ERR" && "$ERR" != "null" ]]; then
                printf '> Sashiko error: `%s`\n' "$ERR"
            elif [[ -z "$INLINE" || "$INLINE" == "null" ]]; then
                printf '_No review output._\n'
            elif [[ "$INLINE" == "No issues found." ]]; then
                printf '%s\n' "$INLINE"
            else
                printf '```\n%s\n```\n' "$INLINE"
            fi
        } | tee -a "$OUTPUT_DIR/comment.md"
    else
        echo "review binary exited non-zero for $SHA" >&2
        {
            printf '\n---\n\n## Patch %d/%d — `%s`\n\n' "$IDX" "$N" "${SHA:0:12}"
            printf '_Review crashed — see workflow logs._\n'
        } | tee -a "$OUTPUT_DIR/comment.md"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
done

echo "Reviewed $N patches, $FAIL_COUNT failures."
echo "SASHIKO_FAIL_COUNT=$FAIL_COUNT" >> "${GITHUB_ENV:-/dev/null}"
