#!/usr/bin/env bash
set -euo pipefail

# Runs the knitpick (review-nitpick.md) skill over a PR's commit range using
# the headless Claude CLI, then assembles a markdown comment for the PR.
#
# Inputs (from env):
#   REPO_PATH    — kernel checkout (PR head); the CLI runs from here
#   PROMPTS_DIR  — review-prompts kernel/ dir (contains review-nitpick.md)
#   BASE_SHA     — PR base commit
#   HEAD_SHA     — PR head commit
#   MAX_PATCHES  — abort if PR has more commits than this
#   MODEL        — bedrock model id (for the comment header; CLI reads ANTHROPIC_MODEL)
#   OUTPUT_DIR   — where to write comment.md + copied review artifacts

: "${REPO_PATH:?}" "${PROMPTS_DIR:?}" "${BASE_SHA:?}" "${HEAD_SHA:?}"
: "${MAX_PATCHES:=35}" "${MODEL:=us.anthropic.claude-opus-4-7}"
: "${OUTPUT_DIR:=$PWD/knitpick-out}"

mkdir -p "$OUTPUT_DIR"

mapfile -t COMMITS < <(git -C "$REPO_PATH" log --reverse --format='%H' "$BASE_SHA..$HEAD_SHA")
N=${#COMMITS[@]}

if (( N == 0 )); then
    echo "No commits in $BASE_SHA..$HEAD_SHA — nothing to review."
    exit 0
fi

# Honor an optional partial-review directive (review-num-commits /
# review-git-range) from the PR body or a workflow input. The knitpick CLI runs
# once over a range, so collapse the selected commits back into an effective
# base..head; a full review leaves RANGE_BASE/RANGE_HEAD at the PR's own SHAs.
TOTAL_PR_COMMITS=$N
# shellcheck source=select-commits.sh
source "$(dirname "$0")/select-commits.sh"
SKIP_PREFIX=KNITPICK
select_commits "${COMMITS[@]}"
N=${#SELECTED_COMMITS[@]}
if [[ -n "$REVIEW_SELECTION" ]]; then
    RANGE_BASE="$SELECTED_BASE"
    RANGE_HEAD="$SELECTED_HEAD"
else
    # Full review: keep the PR's own base/head verbatim (SELECTED_BASE would be
    # an equivalent "<first-commit>^" but is noisier in the prompt/header).
    RANGE_BASE="$BASE_SHA"
    RANGE_HEAD="$HEAD_SHA"
fi

if (( N > MAX_PATCHES )); then
    {
        printf '**Knitpick review skipped:** this PR has %d commits, exceeding the limit of %d.\n\n' "$N" "$MAX_PATCHES"
        printf 'Large series take a long time and consume significant model budget. \n'
        printf '**Check that your PR base is correct.** A common cause of an inflated commit count is branching from the wrong base, which pulls in unrelated upstream commits.\n'
        printf 'If your commits are based on another base use one of the following options to review a subset of the commits: \n\n'
        printf '    review-num-commits: <n>          review only the last <n> commits\n'
        printf '    review-git-range:   <sha>..<sha> review only that range (must be subset of PR)\n\n'
    } > "$OUTPUT_DIR/comment.md"
    exit 0
fi

NITPICK_PROMPT="$PROMPTS_DIR/review-nitpick.md"
INLINE_FILE="$REPO_PATH/review-nits-inline.txt"
METADATA_FILE="$REPO_PATH/review-nits-metadata.json"

# Start from a clean slate so stale output from a previous run can't leak in.
rm -f "$INLINE_FILE" "$METADATA_FILE"

echo "Reviewing $N commit(s) with $MODEL via the knitpick skill..."

read -r -d '' PROMPT <<EOF || true
You are in a Linux kernel git checkout at $REPO_PATH.

Read the nit-pick review prompt at $NITPICK_PROMPT and follow it exactly. The
prompt directory (for any files it references relatively, such as
subsystem/subsystem-nits.md and inline-template.md) is $PROMPTS_DIR.

Review the patch series in the commit range $RANGE_BASE..$RANGE_HEAD. Use git
(git log, git show, git format-patch) to read the diffs and commit messages for
those commits. Treat them as the patch series under review.

This is a nit-pick (style, readability, maintainability) review ONLY. Do not
report correctness bugs, security issues, performance problems, or functional
regressions.

Follow the review-nitpick.md protocol's output requirements: write
review-nits-inline.txt (only if nits are found) and review-nits-metadata.json
into the current working directory ($REPO_PATH).
EOF

# Run the skill once over the whole series, from inside the kernel tree.
if ( cd "$REPO_PATH" && claude -p "$PROMPT" \
        --permission-mode bypassPermissions \
        --allowedTools "Read,Write,Edit,Bash,Grep,Glob" \
        > "$OUTPUT_DIR/claude.log" 2>&1 ); then
    echo "Knitpick review completed."
else
    echo "claude CLI exited non-zero — see $OUTPUT_DIR/claude.log" >&2
fi

# Preserve raw skill artifacts for the uploaded artifact bundle.
[[ -f "$INLINE_FILE" ]] && cp "$INLINE_FILE" "$OUTPUT_DIR/"
[[ -f "$METADATA_FILE" ]] && cp "$METADATA_FILE" "$OUTPUT_DIR/"

# Assemble the PR comment. Always produce comment.md so the post step fires.
{
    printf '# Knitpick review\n\n'
    printf 'Style, readability, and maintainability nits only — not a correctness review.\n'
    printf 'The AI nitpicker is highly committed to its job and never stops nitpicking. \n'
    printf 'Please use your discretion to stop iterating on reported issues.\n\n'
    printf 'Model: `%s`  \n' "$MODEL"
    printf 'Base: `%s`  \n' "$RANGE_BASE"
    printf 'Head: `%s`  \n' "$RANGE_HEAD"
    if [[ -n "${REVIEW_SELECTION:-}" ]]; then
        printf 'Partial review: %s — %d of %d commits  \n' \
            "$REVIEW_SELECTION" "$N" "$TOTAL_PR_COMMITS"
    fi
    printf '\n'
    printf -- '---\n\n'

    if [[ -s "$INLINE_FILE" ]]; then
        printf '```\n'
        cat "$INLINE_FILE"
        printf '\n```\n'
    else
        printf 'No style nits found.\n\n'
        printf '_Knitpick only emits nits when a subsystem nit guide matches the touched code; today only x86 has one. If this series touches another subsystem, that is expected._\n'
    fi
} > "$OUTPUT_DIR/comment.md"

echo "Wrote $OUTPUT_DIR/comment.md"
