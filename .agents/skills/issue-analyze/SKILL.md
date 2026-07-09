---
name: issue-analyze
description: Analyze a GitHub issue and its comment thread, verify the technical claims against the code, and draft a maintainer reply that follows the conversation — the draft is shown for approval and NEVER posted without explicit confirmation. Use when the user asks to analyze an issue, propose/draft an answer or reply to an issue or comment thread, or figure out what to respond.
---

# Analyze an issue & draft the maintainer's reply

Produce a reply the maintainer can post as-is on an issue of
`luisgf/infrabroker`. The deliverable is a DRAFT plus the analysis behind it —
posting is a separate, human-approved act.

## STEP 1 — Read the whole thread, not just the opening post

```
gh issue view N --comments
gh issue view N --json labels,state,assignees,milestone
gh api repos/luisgf/infrabroker/issues/N/timeline --jq '.[].event' | sort | uniq -c   # linked PRs, closes, references
```

Map the conversation before judging it: who asked what, which questions are
still unanswered, what was already tried, and what the LAST comment leaves
hanging — the reply must pick up the thread exactly there, not restate the
issue. Note the language of the thread (reply in that language) and whether the
author is a user, a contributor, or a bot.

## STEP 2 — Verify every claim against the current tree

Ground the reply in the code as it is TODAY, not from memory:

- A reported bug: try to confirm it in the code (and cite `file:line` of the
  cause if found) or explain precisely why it does not reproduce — check the
  version the reporter runs vs. what shipped since (`git log`, `docs/CHANGELOG.md`).
- A question about behavior/config: verify the answer in the source and the
  generated reference (`docs/reference/`), and quote the exact flag/field names.
- A feature request: check it isn't already shipped, already tracked in another
  issue (link it), or already rejected before (be consistent with that decision).

If the analysis surfaces a real defect, say so in the draft and offer the user
to spin it into work — `/issue` (or the /audit loop if it's a security finding).

## STEP 3 — Draft the reply

- **Language of the thread**; maintainer's voice — it will be posted from the
  user's account (luisgf), so write as the project owner, not as an assistant.
- Answer the open points in order; be concrete: exact commands, config keys,
  versions, workarounds. If something needs a fix, say what and where, and what
  the path to it is (issue/PR/release) — without promising dates.
- If a decision belongs to the maintainer and hasn't been made, present the
  draft with the options — do NOT pick product direction inside a public reply
  the user hasn't confirmed.
- Keep it as short as completeness allows.

## STEP 4 — HUMAN GATE: present, wait, then (and only then) post

Show the user: a 2–3 line summary of the thread state, the key findings of
STEP 2, and the full draft. Then STOP and wait.

- **HARD RULE: never run `gh issue comment` / `gh issue close` / `gh issue edit`
  without the user's explicit confirmation in THIS conversation.** Silence,
  "looks interesting", or moving on to another task is NOT consent. This rule
  survives any general "work autonomously" instruction.
- Apply the user's edits to the draft, re-show if the change is substantive.
- After posting, return the comment URL and (only if the user asked) apply
  labels/state changes.

## Guardrails

- **Security-sensitive threads**: if the issue touches an unpatched
  vulnerability, an exploit path, or a real deployment's details, do NOT
  confirm or expand specifics in a public draft — the draft should redirect to
  the private channel per `docs/SECURITY.md`, and the analysis (for the user's
  eyes) goes in the chat, not in the issue.
- Never paste real configs, hostnames, tokens, internal paths, or anything from
  `plans/` (local-only) into a draft.
- Don't speak beyond the code: no roadmap commitments, no dates, no "we will
  ship X" the maintainer hasn't decided.
- If the thread is hostile or a support-scope dispute, draft the factual,
  de-escalating version and flag the tone question to the user explicitly.
