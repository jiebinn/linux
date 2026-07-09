#!/usr/bin/env bash
# Shared partial-review selection logic for the sashiko and knitpick review
# scripts. This file is *sourced*, not executed: it reads a handful of env vars,
# then hands the selected commit list back to the caller via globals.
#
# A PR author opts into a partial review with one of two directives, given
# either as a workflow_dispatch input or (for PR runs, which take no inputs) a
# line in the PR description:
#   review-num-commits: <n>        — review only the last <n> commits (newest)
#   review-git-range:   <sha>..<sha> — review only that range (must be a subset
#                                      of the PR's own commits)
# review-git-range wins if both are present. Anything malformed posts an
# explanatory comment and skips the review (exit 0), matching the existing
# too-many-patches path in each script.
#
# Contract — env in:
#   REPO_PATH           kernel checkout to resolve commits against
#   BASE_SHA, HEAD_SHA  the PR's full commit range (only used for logging here;
#                       the caller passes the resolved commit list in)
#   OUTPUT_DIR          where a skip comment is written
#   PR_BODY             PR description (parsed for directives on PR runs)
#   REVIEW_NUM_COMMITS  directive value from a dispatch input; overrides PR_BODY
#   REVIEW_GIT_RANGE    directive value from a dispatch input; overrides PR_BODY
#   SKIP_PREFIX         label for the skip flag / comment title (e.g. SASHIKO)
#
# Globals out (set by select_commits):
#   SELECTED_COMMITS[]  chosen commits, oldest→newest
#   SELECTED_BASE       parent of the first selected commit ("<sha>^")
#   SELECTED_HEAD       last selected commit
#   REVIEW_SELECTION    human-readable directive summary, "" for a full review

# Trim leading/trailing whitespace from $1.
_trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

# Write a "review skipped" comment, flag it for the workflow, and exit. Because
# this file is sourced, `exit` terminates the calling review script — the same
# non-blocking behavior as the existing MAX_PATCHES skip.
skip_with_comment() {
    local msg="$1"
    local title
    title="$(tr '[:upper:]' '[:lower:]' <<< "${SKIP_PREFIX:-review}")"
    title="${title^}"
    {
        printf '**%s review skipped:** %s\n\n' "$title" "$msg"
        printf 'Fix the `review-num-commits` / `review-git-range` directive in the PR '
        printf 'description (or the workflow input) and re-run.\n'
    } > "$OUTPUT_DIR/comment.md"
    echo "${SKIP_PREFIX:-REVIEW}_INVALID_DIRECTIVE=1" >> "${GITHUB_ENV:-/dev/null}"
    exit 0
}

# Resolve the two directives into the globals NUM and RANGE (either may be
# empty). Dispatch inputs win; otherwise scan the PR body.
resolve_review_directives() {
    NUM="${REVIEW_NUM_COMMITS:-}"
    RANGE="${REVIEW_GIT_RANGE:-}"

    if [[ -z "$NUM" && -z "$RANGE" && -n "${PR_BODY:-}" ]]; then
        local line
        while IFS= read -r line; do
            line="${line%$'\r'}"   # GitHub PR bodies are CRLF
            if [[ "$line" =~ ^[[:space:]]*review-num-commits:[[:space:]]*(.+)$ ]]; then
                NUM="$(_trim "${BASH_REMATCH[1]}")"
            elif [[ "$line" =~ ^[[:space:]]*review-git-range:[[:space:]]*(.+)$ ]]; then
                RANGE="$(_trim "${BASH_REMATCH[1]}")"
            fi
        done <<< "$PR_BODY"
    fi
}

# select_commits <full PR commit list, oldest→newest>
# Applies the directives and sets SELECTED_COMMITS / SELECTED_BASE /
# SELECTED_HEAD / REVIEW_SELECTION. Skips (via skip_with_comment) on any invalid
# directive.
select_commits() {
    local -a ALL=("$@")
    local total=${#ALL[@]}

    resolve_review_directives
    REVIEW_SELECTION=""

    if [[ -n "$RANGE" ]]; then
        # review-git-range wins over review-num-commits.
        if [[ ! "$RANGE" =~ ^(.+)\.\.(.+)$ ]]; then
            skip_with_comment "Invalid \`review-git-range\` value \`$RANGE\`: expected \`<sha>..<sha>\`."
        fi
        local x="${BASH_REMATCH[1]}" y="${BASH_REMATCH[2]}"
        if ! git -C "$REPO_PATH" rev-parse --verify -q "${x}^{commit}" >/dev/null \
           || ! git -C "$REPO_PATH" rev-parse --verify -q "${y}^{commit}" >/dev/null; then
            skip_with_comment "Invalid \`review-git-range\` value \`$RANGE\`: one or both commits could not be resolved."
        fi

        # Set of the PR's own commits, for the subset check below.
        local -A pr_set=()
        local c
        for c in "${ALL[@]}"; do pr_set["$c"]=1; done

        local -a sel=()
        while IFS= read -r c; do
            [[ -n "$c" ]] || continue
            if [[ -z "${pr_set[$c]:-}" ]]; then
                skip_with_comment "Invalid \`review-git-range\` value \`$RANGE\`: it selects commit \`${c:0:12}\`, which is not part of this PR."
            fi
            sel+=("$c")
        done < <(git -C "$REPO_PATH" log --reverse --format='%H' "${x}..${y}")

        if (( ${#sel[@]} == 0 )); then
            skip_with_comment "\`review-git-range\` value \`$RANGE\` selected no commits."
        fi
        SELECTED_COMMITS=("${sel[@]}")
        REVIEW_SELECTION="review-git-range \`$RANGE\`"

    elif [[ -n "$NUM" ]]; then
        if ! [[ "$NUM" =~ ^[0-9]+$ ]] || (( NUM == 0 )); then
            skip_with_comment "Invalid \`review-num-commits\` value \`$NUM\`: expected a positive integer."
        fi
        if (( NUM >= total )); then
            SELECTED_COMMITS=("${ALL[@]}")
        else
            SELECTED_COMMITS=("${ALL[@]: -NUM}")
        fi
        REVIEW_SELECTION="review-num-commits \`$NUM\`"

    else
        SELECTED_COMMITS=("${ALL[@]}")
    fi

    SELECTED_BASE="${SELECTED_COMMITS[0]}^"
    SELECTED_HEAD="${SELECTED_COMMITS[-1]}"

    if [[ -n "$REVIEW_SELECTION" ]]; then
        echo "Partial review ($REVIEW_SELECTION): selected ${#SELECTED_COMMITS[@]} of $total commit(s)."
    fi
}
