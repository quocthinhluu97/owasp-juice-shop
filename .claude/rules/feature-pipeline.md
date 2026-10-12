# Feature pipeline

Every feature or phase change goes through four stages in this order, each with its own agent (`.claude/agents/`). Don't skip or reorder stages.

```
researcher → plan-writer → [human review] → implementer → code-reviewer
```

## 1. Research (`researcher`)

- Collect what the plan needs: current tool versions and image digests, flags, output formats, what's already in the repo, and the rules that apply.
- The output is a sourced summary. It decides nothing.
- Skip this stage only when the change needs no outside facts (e.g. a typo fix). Say that you're skipping it.

## 2. Plan (`plan-writer`)

- Claude drafts the plan from the research: steps, files to change, how to check each step, and decisions with reasons. Choices that belong to the user are marked **(you)** or `TODO:`.
- `plan-writer` saves it to `.claude/plans/<short-kebab-name>.md` and links it from `roadmap.md`.

## 3. Human review (gate)

- **Stop after the plan is written.** Give the user the plan path, a short summary, and the open questions. Then wait.
- Implement only after the user explicitly approves. Silence, or approval of an earlier plan, doesn't count.
- If the user asks for changes, `plan-writer` updates the plan and you ask again. Record the approval in the plan (`Approved: YYYY-MM-DD`).

## 4. Implement (`implementer`)

- Give it the approved plan's path and the steps to do. It follows the plan and nothing else.
- If it stops on an unclear or wrong step, update the plan (stage 2) and ask for review again (stage 3) before continuing. Don't let it improvise.
- In scanner phases, the "guide, don't do" preference still applies: steps marked **(you)** (running scanners, judging findings) stay with the user.

## 5. Review (`code-reviewer`)

- Review the final state of the change against `.claude/rules/`.
- Fix what it finds by sending the fixes back through `implementer` (or through the plan, if a fix changes the design). Then review again until it comes back clean, or the user accepts what's left.
- Commit only after a clean review, and only when the user asks. Update the plan's status (✅) through `plan-writer`.
