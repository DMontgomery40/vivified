# Merge Queue Setup (GitHub)

To prevent broken commits from merging and to serialize concurrent merges safely, enable Merge Queue on your protected branches (e.g., `development`, `main`).

Steps (requires admin permissions):

- Branch protection rules (Settings → Branches → Add rule):
  - Branch name pattern: `development` (repeat for `main` if desired)
  - Require a pull request before merging
  - Require approvals: 2 (3 for security changes)
  - Require status checks to pass before merging
    - Add required checks:
      - `lint` (Python linters)
      - `test` (unit tests)
      - `ui-build` (core/ui)
      - `admin-ui-build` (core/admin_ui)
      - `docker-core-image` (integration smoke)
  - Require branches to be up to date before merging
  - Require conversation resolution before merging
  - Enable **Allow auto-merge**
  - Enable **Merge queue**

Merge Queue behavior:

- New merges are batched and validated together at the tip of the queue.
- Only the queue head is built/tested against the latest base; once green, it merges automatically.
- Prevents “green-on-HEAD, red-when-rebased” failures.

Recommended repository settings:

- Dismiss stale approvals when new commits are pushed.
- Restrict who can push directly to protected branches (enforce PRs).
- Require signed commits if applicable.

Local workflow:

- Run `make ci-local` and `make ui-ci-local` before every push (or rely on pre-push hooks set in `.pre-commit-config.yaml`).
- Use the optional `tools/scripts/agent_gate.py --wait-merge` to block automation until the PR is merged with green checks.

