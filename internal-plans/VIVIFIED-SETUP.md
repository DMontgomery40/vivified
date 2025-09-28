Vivified Enterprise Modular Platform Blueprint
Monorepo Repository Structure and Conventions

Repository Layout: Organize the platform as a single monorepo containing the core platform, official plugins, SDKs for multiple languages, documentation, and build tools. This structure ensures all components use a shared canonical model and simplifies cross-component changes. A clear top-level folder layout is critical for scale and clarity:

core/ – The core platform services and libraries (orchestrator, gateway, policy engine, etc.). This houses common logic and the canonical schema definitions (e.g. Protocol Buffers files and generated code).

plugins/ – Default plugin implementations (each in a subfolder). For example, plugins/identity/, plugins/email/, etc., each containing that plugin’s code, config, and Docker setup. Plugins are built as independent services (Docker containers) in any language so long as they adhere to the core API contracts.

sdk/ – Language-specific SDKs that developers use to build plugins:

sdk/python/ – Python SDK (e.g. Pydantic models, FastAPI client stubs, gRPC stubs).

sdk/nodejs/ – Node.js SDK (TypeScript types, client libraries).

sdk/go/ – Go SDK (Go structs and client interfaces).

tools/ – Utility scripts and tools for development and CI. For example, scaffolding scripts, schema generators, or custom linters. This may include a scripts/ subfolder (for automation like Docs Autopilot integration) and CI configuration in .github/workflows/.

docs/ – Documentation source (MkDocs markdown files, images, etc.) along with mkdocs.yml. This contains all user and developer guides. (See Documentation Pipeline for branch strategy on docs.)

Other top-level files: Makefile, README.md, AGENTS.md (developer-agent guidelines), .gitignore, etc.

<details><summary>**Example Repository Tree** (partial)</summary>
/ Makefile                   # Common build tasks
/ mkdocs.yml                 # MkDocs configuration for docs site
/ .github/workflows/         # CI/CD workflows (tests, docs, deploy)
/ core/
    proto/                   # Protobuf IDL definitions for canonical models
    gateway/                 # Core API gateway (e.g. FastAPI app)
    policy/                  # Policy engine modules
    ... (other core services)
/ plugins/
    identity/                # Identity plugin (example)
        Dockerfile
        identity_service.py  # (if Python plugin) or index.js, etc.
        manifest.yaml        # Plugin manifest declaring traits, contracts, etc.:contentReference[oaicite:2]{index=2}
    email/                   # Email plugin (example)
        Dockerfile
        ...                  
/ sdk/
    python/
        vivified_sdk/        # Python SDK package (to be published to PyPI)
    nodejs/
        vivified_sdk/        # Node.js SDK (npm package)
    go/
        vivified_sdk/        # Go SDK module
/ tools/
    cookiecutter-template/   # (Optional) Template for new plugin projects
    scripts/
        docs_autopilot.py    # Script to run Docs-Autopilot for doc updates
        ... 
/ docs/
    index.md
    plugins.md
    ... (other markdown docs)

</details>

Naming & Coding Standards: Use consistent naming conventions across the repo:

All directories and files use lowercase and hyphen/underscore separation (e.g. canonical_model.proto, plugin-manifest.yaml).

Python code follows PEP8 style (use tools like Black and Flake8). Node.js projects use ESLint/Prettier with a standard style (e.g. Airbnb or Google style). Go code uses gofmt/goimports and idiomatic naming.

Schemas/IDLs: Define all cross-language contracts in a neutral format (Protocol Buffers for events and gRPC, OpenAPI for REST endpoints). For example, canonical event schemas are in .proto files under core/proto/. These serve as the single source of truth for all services and SDKs. Generated code in each SDK should not be hand-edited.

Internal APIs: The core will expose gRPC services and/or REST endpoints (via FastAPI or gRPC server) for operator calls. Use clear, versioned API paths (e.g. /v1/identity/getUser) and maintain an OpenAPI spec for any HTTP interfaces (to allow client generation and documentation).

Common Build Tasks (Makefile): Provide a top-level Makefile to streamline development across languages. Include phony targets for frequent tasks:

make install – Install all dependencies (could call sub-language package managers, e.g. pip, npm, go modules).

make build – Build or compile all components (e.g. generate protos, compile Go binaries, build Docker images).

make test – Run all unit tests across core and plugins (e.g. via Pytest, Jest, Go test).

make lint – Run linters/formatters (Python lint + type-check, ESLint, Go vet).

make run – Launch the core and some default plugins for local dev (perhaps via docker-compose or a dev script).

make docs – Build the documentation site locally (using MkDocs).

make proto – Regenerate SDK code from protobuf definitions (wrapping buf generate or protoc commands).

make clean – Clean up any build artifacts.

These Makefile commands standardize the workflow for all contributors (human or agent). For example, an agent can call make test to ensure its changes pass all tests before making a PR. Below is a snippet of how tasks can be defined:

# Makefile sample (excerpt)
.PHONY: install build test lint

install:
\tpip install -r core/requirements.txt
\tnpm install --prefix sdk/nodejs
\tgo mod download ./sdk/go/...

build: proto
\tdocker build -t vivified/core:dev ./core
\tdocker build -t vivified/identity:dev ./plugins/identity

test:
\tpytest -q core/tests
\tnpm test --prefix sdk/nodejs
\tgo test ./sdk/go/...

lint:
\tflake8 core plugins
\teslint -c sdk/nodejs/.eslintrc.js \"sdk/nodejs/**/*.ts\"
\tgolint ./sdk/go/...


(Agents should use these commands instead of ad-hoc steps to ensure consistency.)

Dockerfiles & Layered Caching: Each major build artifact (core and each plugin) should have a Dockerfile with a multi-stage build to optimize caching. For example, a Dockerfile for a Python service might first copy and install requirements.txt (this layer is reused until dependencies change), then copy the source code. This way, code changes don’t invalidate the dependency layer. Base images should be pinned to specific versions (with regular updates) to ensure repeatability. A recommended strategy is to maintain a base builder image (updated weekly) that includes OS packages and language runtimes, so CI can pull this and build on top rather than starting FROM scratch each time. This dramatically speeds up CI builds by caching heavy dependencies.

Git Branching Strategy: Adopt a simple branch model to separate stable releases from ongoing development:

main – Protected branch representing production-ready code. No direct commits are allowed to main (enforced via branch protection); all changes land via pull requests that have passed CI and code review.

development – The default integration branch where active development happens. Developers and agents branch off from development and open PRs back into it. Continuous integration runs on these PRs, and upon merge, triggers staging deployments and documentation updates.

staging – A pre-production branch used for release candidates. For example, when development has accumulated enough features for a release, it may be merged into staging for further testing in a staging environment. This branch is also protected; only merge from development is allowed. (Optional: some teams may merge development → main directly and use tags for staging. The exact flow can be adjusted.)

feature/* or agent/* – Short-lived branches for specific features or automated agent tasks. For instance, an agent fixing a bug or adding a small feature might use a branch named agent/fix-issue-123. These are merged into development when ready.

Workflow Guardrails: All contributions, especially those by AI agents, go through the PR process on the development branch – never committing directly to protected branches. This guarantees that tests and reviews gate every change. Branch protections on main (and development if desired) will require:

Passing CI checks (lint, tests, build) before merge.

At least one approval for human-written PRs. Agent PRs might be auto-approved by a designated bot account, but still require CI passing.

Linear history (e.g. squash merges) to keep history clean.

AGENTS Development Framework (AGENTS.md)

Purpose: The AGENTS.md file defines how AI "agent" contributors interact with the repo. It provides step-by-step guidelines, ensuring agents remain short-context (only focus on the relevant instructions for the current phase of work), are test-aware (always run/consider tests), and have battle-tested procedures for reliable contributions. By codifying this, we reduce context window usage and direct the agent’s focus to the task at hand, improving outcome quality.

Structured Phases: Break down the agent’s work into discrete phases, each with specific instructions. This ensures the agent only loads the instructions needed for its current phase, keeping context short. For example:

Phase 0: Initialization – (Planning) If the agent is starting a new task or feature, it should read the issue/ticket and possibly update AGENTS.md with a plan checklist. Instruction: “Draft a plan. Do not write code yet. If Phase 0 complete, proceed to Phase 1.”

Phase 1: Implementation – (Write code) The agent focuses on coding the core logic (plugin or core feature). It should include unit tests for new code. Instruction: “Implement the feature in the appropriate module. Ensure to update or add tests. After coding, run make test. If tests pass, proceed to Phase 2.”

Phase 2: Testing & Verification – The agent runs tests and linters. If anything fails, it fixes the issues. Instruction: “Run make lint and make test. If failures occur, fix them and re-run until green. If all tests pass, move to Phase 3.”

Phase 3: Documentation Update – The agent updates docs if needed (e.g. user docs or inline API docs) corresponding to the changes. It may invoke the Docs Autopilot tool to assist (see Docs Pipeline). Instruction: “Update relevant docs (in docs/ or code comments). If in Phase 3 and docs are updated, proceed to Phase 4.”

Phase 4: Pull Request – The agent prepares a PR. Instruction: “Open a PR to development with a clear title and description of changes. Include in the PR description: ‘Resolves #issue’ if applicable. Then monitor CI results.” The PR description can also list checkboxes from Phase 0’s plan, marking tasks as done.

Each phase section in AGENTS.md is labeled (e.g. "## Phase 2: Testing") so an agent can jump directly to it. Include guidance like “If you are an agent in Phase 2, skip directly to the Phase 2 section below” to enforce the short-context principle (the agent will ignore other phases’ instructions when not needed). This conditional reading approach ensures the agent isn’t overwhelmed with instructions irrelevant to its current step.

CI Integration and Auto-Merge: Agents should rely on CI feedback as a primary gatekeeper:

After pushing commits to a PR, an agent enters a sleep-check-sleep loop: it will pause for a certain time (e.g. 60 seconds), then check the CI status via GitHub API, repeating this until results are in. If CI fails, the agent wakes up to read logs and then returns to the appropriate phase (likely Phase 1 or 2) to fix the issues. If CI passes, the agent can proceed to finalize the PR.

We configure GitHub Actions to comment on the PR or set a commit status that the agent can parse for results (like “All checks passed” or which tests failed).

Auto-merge: If a PR is opened by an agent and all checks pass, a GitHub Action (or bot) can automatically merge the PR into development
GitHub
. This should happen only if certain conditions are met (no human requested changes, all required checks green). If auto-merge fails (e.g. due to new commits or branch out-of-date), the agent should rebase or update the branch, then retry.

Battle-Tested Practices: The AGENTS.md should accumulate proven tips and guardrails from real runs. For example:

Remind agents to search the codebase for similar implementations to mimic style.

Emphasize running only relevant tests (agents could run a targeted test suite for a plugin instead of all tests, to save time).

Provide known fixes for common pitfalls (e.g. “If you see a flaky test around X, try Y”).

Ensure no sensitive data is included in prompts or outputs – the instructions in AGENTS.md are public-safe by design (no secrets or keys)
GitHub
, so they can be shared with AI services without leaking sensitive info.

Dynamic Instructions Example: Below is an excerpt illustrating phase-specific guidance in AGENTS.md:

## Phase 1: Implementation (Coding)
- Focus: Implement required functionality in the appropriate module or plugin.
- Read: The design notes in docs or any examples in similar modules.
- Do: Write code and corresponding unit tests. Ensure code style guidelines are followed.
- Next: Upon completion, run `make test`. If tests pass, move to Phase 2. If not, fix and stay in Phase 1.

*(If you are an agent and have completed Phase 1, you may skip ahead to Phase 2 instructions.)*

## Phase 2: Testing & Verification
- Focus: Verify all tests and linters pass in CI.
- Do: Run `make lint` and `make test`. Review any failing test output or linter messages carefully.
- Fix: Address any issues, then re-run tests until they all pass.
- Next: If all checks are green, proceed to Phase 3.

...


This way, an agent reading the file will hone in on the Phase 2 section only when relevant, keeping the rest collapsed or out-of-scope, thereby staying within context limits.

CI/CD Pipeline Strategy

Continuous Integration (CI) on Pull Requests: Use GitHub Actions to run a full test suite on every PR and enforce quality:

For every pull request targeting development (or staging/main), trigger workflows for linting, unit tests, and build (compilation). This ensures no code that breaks tests or style guidelines gets merged. For example, a workflow .github/workflows/ci.yml can run on pull_request events, executing make lint, make test, etc., in parallel jobs for different components.

Incorporate matrix builds if needed (e.g. test against multiple Python or Node versions, or multiple database backends if applicable). This catches compatibility issues early.

Use caching in CI to speed up builds: GitHub Actions cache for dependencies (pip caches, npm cache, Go modules) and Docker layer caching if possible. For instance, cache ~/.cache/pip and $GOPATH/pkg between runs. Also consider a self-hosted runner or service for Docker builds to reuse layers.

Docker Build Optimization: To avoid rebuilding base layers on each CI run, build images on top of a cached base. A good practice is to maintain a base image (with OS updates, language runtimes, common packages) updated weekly. CI can pull vivified/base:latest (refreshed periodically) and then copy in the latest code. This way, the heavy apt-get or language runtime install steps are not repeated on every commit, only the incremental code layers are built. A scheduled workflow (e.g. every Sunday night) can rebuild and push the updated base image from Dockerfile (ensuring security patches are included weekly). The PR CI then uses --cache-from=vivified/base:latest when building.

Branch Protections & Policies: Enable protections on main (and development) such as:

Require status checks: PRs must pass CI checks (tests, lint) before merge.

Require review: Optionally, at least one human review for any code changes that affect critical parts (security-sensitive code, core services). Agent-made PRs might be auto-approved by a maintainer after inspection.

Disallow direct pushes: Only the CI or designated bot can push to main (for example, the release workflow or Docs deployment can push to gh-pages or merge via bot).

Enforce conventional commits or semantic PR titles if desired (for consistent changelogs).

Automated Merging: Set up a GitHub Action (or use a tool like peter-evans/enable-auto-merge) to automatically merge PRs when checks succeed. This is especially useful for agent-generated PRs: once tests pass, the PR can merge without manual intervention. The agent, as noted, will monitor this. If a merge fails (e.g., due to new commits in development causing conflict), the agent should fetch the latest development, rebase its branch, resolve conflicts, and push an update, then again wait for CI and merge. This loop continues until merged or a human intervenes.

Post-Merge Actions: When changes land in development:

Staging Deployment: A workflow can deploy the new development build to a staging environment (if applicable). For instance, build and push Docker images with a :staging tag, or update a Kubernetes staging namespace. This keeps staging up-to-date for QA.

Main Release Pipeline: Merging into main (which might happen periodically or via a release manager) triggers production build/deployment workflows. These could include tagging a release, publishing artifacts (e.g., SDK packages to PyPI/NPM, Docker images to registry), and notifying relevant parties.

Docs Integrity & CI: Documentation should be treated as code. Add CI steps to validate docs:

Run mkdocs build --strict to catch any MkDocs config or linking errors. Also run Docs-Autopilot in plan mode to see if it suggests changes (though this might be more of a daily job than per-PR).

Use mike (MkDocs versioning tool) to ensure the versioned docs strategy is consistent (e.g., the mkdocs.yml contains the expected versions and aliases).

If any doc generation step fails, mark the CI as failed. This prevents broken documentation from slipping in.

Summary of CI flows:

Trigger	Action
Pull Request to development	Run lint, tests, build (all languages). Post status checks. No deployment, just verification.
Merge to development	(Post-merge) Optionally deploy to staging environment; run Docs Autopilot to propose doc changes (see Docs Pipeline).
Scheduled (e.g. weekly)	Rebuild base images, refresh caches; run security scans (dependency audit) and report issues.
Merge to staging	Deploy to staging (if not already on dev merge) and run any integration tests against staging environment.
Merge to main (release)	Trigger production deployment workflows, publish SDKs (PyPI, NPM, etc.), and tag release. Also trigger documentation publish if needed.
Push to mkdocs (docs site)	Trigger docs site build and deploy to gh-pages (Doc Pipeline).

No code goes untested or unreviewed in these flows, preserving a high bar for quality even as AI agents contribute.

Documentation Pipeline

Documentation is maintained as Markdown in the repository and auto-deployed to a documentation site. We integrate MkDocs (with the Material for MkDocs theme for user-friendly nav and search) and mike for versioning. The pipeline encourages continuous documentation updates alongside code changes, using automation to alleviate the burden.

Branch Strategy for Docs: We adopt a branch split inspired by Faxbot’s approach
GitHub
:

The mkdocs branch serves as the working branch for documentation updates. All documentation source (/docs folder and mkdocs.yml) is version-controlled here. Agents (and humans) will propose documentation changes on this branch.

The gh-pages branch is used to publish the static site. A GitHub Pages or Netlify process will serve the content of gh-pages. We configure GitHub Pages to use gh-pages branch (with / root) and set a custom domain (CNAME) of docs.vivified.dev for the site.

This separation means the main code branches are not cluttered with documentation site builds. Instead, docs are updated in parallel and published atomically.

Docs-Autopilot Integration: We leverage Docs-Autopilot
GitHub
 to keep documentation in sync with code changes:

A GitHub Action (workflow) triggers on push to development. This workflow runs Docs-Autopilot in "plan" mode to analyze the code diff and produce a markdown file (or artifact) summarizing what docs might need updates
GitHub
.

The workflow then switches to the mkdocs branch and applies the suggested changes (optionally using an LLM if configured) to the markdown files. It commits these changes in mkdocs and opens a PR (from mkdocs branch) for review
GitHub
.

An agent (or a designated docs bot) can then review this PR. If the changes are sensible (or after human review), the PR is merged into mkdocs branch. Since mkdocs is the default docs working branch, we can even auto-merge if the diff touches only docs and passes checks.

Once documentation changes are in mkdocs branch, another Action kicks off to deploy the docs. Using MkDocs and mike, the action builds the static site:

It might run mkdocs build and then use mike to publish a new version (e.g., "latest" for the development version of docs). For example, mike deploy --update-aliases 1.0 latest could be used when releasing version 1.0, updating the "latest" alias to it. Initially, we might just maintain a single "latest" version until versioning is needed.

The built site is then committed to the gh-pages branch. This can be done by the official MkDocs action or a custom script (the Faxbot project uses a workflow .github/workflows/mkdocs-deploy.yml to do this
GitHub
).

Publishing: GitHub Pages (or Netlify) will detect the new commit on gh-pages and publish the site. We include a CNAME file in docs/ (or directly add it to gh-pages on first publish) with docs.vivified.dev so that the site is accessible at that friendly URL.

Ensuring Documentation Quality: The docs pipeline should also validate that documentation stays up-to-date:

The Docs-Autopilot "plan" artifact (a checklist of doc changes) can be attached to each release or PR, so maintainers see what docs should be updated. This raises visibility if something was not documented.

A link-checker or MkDocs in strict mode runs in CI to catch broken links or formatting errors in docs. This is part of the Docs integrity check in the CI pipeline.

We also consider Docs versioning early. Using mike, we can maintain multiple versions of the docs (e.g., if we have both a stable release and a development version). Agents should know to update the unreleased docs (on mkdocs branch, which represents the upcoming version). When a new version is released (merged to main), we would run mike to snapshot that version on the site and keep latest pointing to the newest.

Auto-Updates on Plugin Merge: When an agent merges a plugin or feature change into development, the expectation is that docs are updated in tandem. There are two ways this happens:

The agent itself, in Phase 3, may have directly edited some documentation markdown in the PR (especially if it's a big feature with user-visible changes).

The Docs-Autopilot catches any remaining needed updates by examining the code diff. For example, if a new API endpoint was added, the autopilot might suggest adding a snippet in the API reference docs.

Thus, after a successful merge, the docs branch will shortly get a PR with updates
GitHub
. We require that the docs PR be merged (and docs site deployed) as part of the “definition of done” for a feature. This keeps documentation continuously in sync with the code.

Finally, set up docs.vivified.dev. In the repo settings, enable GitHub Pages for the gh-pages branch and add a DNS CNAME record for docs.vivified.dev pointing to GitHub Pages. Include a CNAME file in the gh-pages output with docs.vivified.dev to signal the custom domain. This way, our documentation is accessible at a professional URL. (If using Netlify as in Faxbot’s case, Netlify can be configured to pull from the GitHub Pages branch as a backup, but using GitHub Pages directly is straightforward here.)

SDK and API Strategy

To maximize adoption and flexibility, Vivified will provide SDKs in multiple languages (initially Python, Node.js, and Go), while keeping core protocols language-neutral. The design ensures that all plugins, regardless of language, speak the same “canonical language” of the platform.

Language-Neutral Core Definitions: Define all data models and service interfaces in an IDL (Interface Definition Language) that is language agnostic:

Use Protocol Buffers (protobuf) to define canonical event schemas and gRPC service definitions (for operator calls). Protobuf is efficient and widely supported, aligning with Vivified’s need for low-latency, typed contracts. Every canonical message type (e.g. UserCreated, InvoicePaid) is defined in .proto files under core/proto. These serve as the single source of truth for both core and plugins.

Optionally use OpenAPI (Swagger) specifications for any RESTful HTTP APIs (e.g., if some core services also expose HTTP endpoints through API Gateway). OpenAPI can complement protobuf: for any functionality not easily expressed as gRPC (file uploads, streaming to browsers, etc.), an OpenAPI YAML/JSON defines it. This spec can then be used to generate client code or documentation.

SDK Generation: From the above schemas, automatically generate SDK code for each language:

Python SDK: Use protoc with Python plugins (e.g. grpcio-tools) to generate Python classes for messages and gRPC stubs. On top of that, provide a Pythonic helper layer (in sdk/python/vivified_sdk) – for example, Pydantic models that wrap the proto classes for easier validation and usage in FastAPI, and high-level methods for publishing events or calling core services. The Python SDK will also include any runtime support needed (like a client to connect to NATS for events, gRPC clients for operator calls, etc.).

Node.js SDK: Use a tool like grpc-tools or ts-proto to generate TypeScript definitions and client stubs from the proto files. Provide a lightweight Node SDK that wraps these stubs, handles authentication tokens, and provides convenience methods (e.g., a function to easily emit a canonical event to the bus). Ensuring TypeScript typings in the SDK will catch integration errors at compile time for plugin developers.

Go SDK: Use protoc-gen-go and protoc-gen-go-grpc to generate Go structs and interfaces from the protos. The Go SDK might be more minimal (since Go developers often use the generated code directly), but we can still provide utility functions (for example, to load config or to easily start a subscriber on a canonical event topic).

All SDKs must implement the same core contracts. For example, if there’s a canonical envelope message with fields trace_id, event_id, canonical_type, etc., every SDK should expose these and provide helper methods to construct or parse them. The transformation interfaces (to convert plugin’s internal data to/from canonical form) should also be consistent across SDKs. The Vivified design mandates that plugins register their data transformers via the SDK, which the core then uses to wire data flows. For instance, a plugin might call sdk.registerTransformer(from="PluginUser", to="User", version="v2", fn=transform_func) in its init, and the core will pick that up to know how to translate the plugin’s user model to the canonical User model.

Python-First Core: We will implement the core platform services in Python for fast development and flexibility. Using frameworks like FastAPI for the HTTP/gRPC gateway and asyncio or NATS.py for event bus integration will allow quick iteration. The core will use the same protobuf definitions – e.g., using generated Python classes for messages – and enforce schema versioning rules. Python’s rich ecosystem (SQLAlchemy for DB, Pydantic for modeling, etc.) accelerates development. Once the Python core proves the design, performance-critical parts can be revisited (or rewritten in Go/Rust if needed in future for optimization, but early on, Python will suffice given internal cluster environment and the target p50 latencies of a few milliseconds).

Protocol Boundaries: Clearly delineate what’s language-neutral vs. language-specific:

The canonical schema (protobuf) and any OpenAPI specs are maintained in the repo (likely under core/ or a dedicated schemas/ folder). These are source-controlled and versioned. Changes to them require careful review since they impact all SDKs and backward compatibility (the schema registry in core will manage versions).

The generated code for each SDK can be committed to the repo (under sdk/*) to simplify usage, or we can generate on the fly. Committing it has the advantage that plugin developers can just import the SDK package without needing to run proto generation themselves. We will likely check in the generated stubs and update them whenever the proto definitions change (enforced via make proto).

Any language-divergent logic (like idiomatic patterns) should be confined to that SDK’s implementation. For example, the Python SDK might do something special with Django integration (if a plugin is Django-based), whereas the Node SDK might integrate with Express – but these specifics don’t affect core protocols.

Ensuring Consistency: Use tools like Buf to lint and validate protobuf changes (Buf’s breaking change detector can ensure we don’t unintentionally break compatibility between versions
buf.build
buf.build
). Also generate an SDK contract test: a small suite that loads each SDK in its language and attempts to send a message from one and receive in another (to verify the wire compatibility). For instance, serialize a canonical event in Python, deserialize in Go, ensure all fields match – this can be part of CI to catch any mismatch in schema handling across languages.

In summary, the SDK strategy is to make plugin development as smooth as possible in the developer’s language of choice, while the core maintains strict canonical contracts. A new plugin developer should be able to do: pip install vivified-sdk or npm install @vivified/sdk or go get github.com/vivified/sdk, and get all the needed types, client stubs, and helper functions to interact with Vivified. This encourages a broad community of plugins without forcing everyone into one language.

Development Tooling and Integration

We will integrate a suite of open-source tools (permissively licensed) to accelerate development, enforce policies, and ensure a scalable, safe plugin ecosystem. Each chosen tool avoids heavy vendor lock-in and can be replaced or removed if needed.

Project Scaffolding: To help bootstrap new plugins or modules, use Cookiecutter (BSD-3-Clause license
github.com
) to create templates. We can maintain a template (in tools/cookiecutter-template/) that includes a sample plugin project structure with best practices (manifest file, example transformer, tests, GitHub Actions CI stub). A developer (or agent) can run cookiecutter tools/cookiecutter-template to generate a new plugin scaffold. This ensures consistency (all plugins start with the same baseline structure and config) and saves time. (Alternatives: Yeoman (MIT) for Node, but Cookiecutter is simple and Python-based, aligning with our core.)

Protocol Buffers Tooling: Use Buf (Apache-2.0 licensed) for protobuf management. Buf provides linting, breaking change detection, and a easy buf generate command to produce code in all languages from a single config
buf.build
buf.build
. This will keep our proto definitions clean and consistent. We’ll configure buf.yaml with our style rules (e.g., field naming conventions, package structure) and buf.gen.yaml with the plugins for Python/TS/Go codegen. Buf’s breaking change feature is especially useful for the canonical schema: if someone modifies a proto in an incompatible way, Buf will catch it before it hits production, enforcing the versioning policy (no removing fields for minor versions, etc., per compatibility rules).

Secure Plugin Sandbox: At runtime, plugins run in containers, but we also enforce restrictions via platform tools:

Use Docker/Kubernetes security options to limit plugin capabilities. For example, enable a seccomp profile and AppArmor for plugin containers to restrict syscalls. This prevents a plugin from escalating privileges.

Leverage Kubernetes NetworkPolicies to only allow plugin pods to communicate with core services and nothing else. As noted in the design, plugins should only talk via official lanes, and Faxbot’s approach was to restrict outbound domains via manifest and network rules. We will implement similar network whitelisting: e.g., a plugin that needs external API access will have to declare it, and only those domains are allowed through the proxy lane.

Consider using gVisor (Apache-2.0) or Kata Containers (Apache-2.0) if we need stronger isolation. These provide lightweight VMs or user-space kernel for containers, adding an extra security layer. They are more complex, so we’d use them only for untrusted third-party plugins.

Integrate Open Policy Agent (OPA) (Apache-2.0) for policy decisions if needed. OPA can enforce fine-grained rules (like “plugin with trait X cannot call endpoint Y”) as code. We might use OPA to evaluate certain security policies at runtime (though core’s own policy engine might suffice initially).

Policy Linting and Schema Validation: Provide tooling to validate configs and manifests:

Define a JSON Schema for the plugin manifest (the file where plugins declare traits, dependencies, etc.). Use a validator (Python’s jsonschema library (MIT) or Node’s Ajv (MIT)) in CI to automatically check that any plugin’s manifest meets the schema (all required fields present, types correct) before allowing it to be merged. This prevents bad plugin descriptors from breaking the plugin loader.

For security policies (traits, roles, etc.), if we externalize them (e.g. in YAML files or OPA policies), use linters for those as well. For example, if using OPA, run opa check on policy files in CI to catch syntax or basic logic errors.

Use ESLint and Flake8 not just for style, but also for identifying forbidden patterns. We can add custom lint rules or checks, for example: disallow using certain Python or Node functions that could be dangerous in plugins (like blocking calls or local file access, if we want to enforce using platform APIs instead). Linters can be extended to encode some policy (e.g., no direct network calls in plugin code – though that’s hard to catch statically, we can try to flag usage of requests library in a plugin that isn’t allowed external calls).

Testing and CI Tools:

PyTest, Jest, and Go’s testing are our choices for respective languages. We add coverage reporting to ensure agents don’t skip writing tests. Possibly enforce a minimum coverage % on PR (using a tool like Codecov or Coveralls).

GitHub Actions is our CI runner; to help developers run workflows locally, we can include act (MIT) usage instructions so they can simulate CI jobs on their machine.

Pre-commit hooks: We can add a pre-commit configuration that runs formatting and linting on commit, to catch issues early (for human devs; agents can also be configured to run these commands before committing).

OpenAPI & Client Generation: If we have an OpenAPI spec for external API (or for our own REST endpoints), use OpenAPI Generator (open-source, Apache-2.0) to generate documentation or client SDKs. For instance, we could generate a TypeScript client for the core’s REST API if any, so plugin front-ends or external integrators can use it. This tool can also ensure our API docs stay updated – whenever we change the FastAPI routes, we update the OpenAPI, and regenerate any necessary code or docs from it.

Documentation Automation: Aside from Docs-Autopilot, consider MkDocs plugins (all open source) to improve docs. For example, the mkdocs-mermaid2 plugin (MIT) for diagrams, or mkdocs-proofcheck for spell checking documentation in CI. These help maintain high quality in the knowledge base.

Miscellaneous: Keep an eye on dependency security:

Use GitHub’s Dependabot (built-in, no license issues) to automate dependency update PRs. This works well in a monorepo to keep Python requirements, npm packages, and Go modules up to date. Each Dependabot PR is small and can be auto-merged if tests pass, ensuring we pull in security fixes promptly.

Integrate a secret scanner (GitHub has secret scanning) to ensure no one accidentally commits API keys or passwords. Agents should be guided not to include secrets, but this will catch any leaks.

Logging and monitoring are part of core, but for development, use tools like Black (MIT) for auto-format, mypy (MIT) for Python type checking, etc., to catch errors early. These are configured in CI as well.

Finally, all these tools are chosen for permissive licenses (MIT, BSD, Apache) to avoid any copyleft complications. They are also modular: for example, if Buf doesn’t suit us later, we can drop it and just use protoc; if OPA is overkill, we stick to simpler YAML policies. We avoid anything that locks us in to a proprietary ecosystem. By assembling this toolchain, we create a robust, automated development environment where contributors (human or AI) can focus on features while the tools and CI guard the quality, security, and consistency of the platform.

Glossary of Key Terms and Roles: (For reference throughout the blueprint)

Term / Role	Definition
Core (Platform Core)	The central service(s) of Vivified that orchestrate plugins. It provides the communication lanes (canonical event bus, operator API gateway, proxy), enforces security and policies, and offers common services (identity, config, etc.). The core mediates all plugin interactions, treating plugins as untrusted by default.
Plugin	A modular extension to the platform, encapsulating a domain-specific feature or integration. Runs in isolation (its own process/container) and communicates with core via defined interfaces. Plugins declare their capabilities and needs in a manifest (including traits, dependencies, transformer functions, and service endpoints). All business logic (HR, Finance, etc.) resides in plugins, making Vivified plugin-first.
Canonical Lane	The event-driven communication channel between plugins through the core. Plugins publish and subscribe to canonical events (standardized messages like UserCreated) on the central event bus (e.g., NATS). Ensures a common data language across the platform. The canonical model engine in core manages the schemas and transformations for these events, so plugins can interoperate seamlessly.
Operator Lane	The direct request-response channel for plugins to call each other’s functionality via core. Implemented as gRPC or REST calls to core’s gateway, which forwards to target plugin services if authorized. Used for on-demand operations (e.g., “get user details”) beyond passive event listening. Requires using canonical IDs and passes through core’s authz checks and auditing.
Proxy Lane	A restricted fallback channel for unusual or external requests. The core acts as a proxy for plugins to perform actions not covered by canonical or operator lanes (e.g., calling a third-party API). The proxy is heavily sandboxed and monitored, only allowing approved domains or actions to prevent abuse. Typically disabled by default; used sparingly for unmodeled integration needs.
Trait	A metadata flag describing a plugin’s characteristics or requirements. Examples: handles_phi (plugin handles protected health info), requires_encryption, provides_ui. Traits inform security decisions and UI behavior. Core uses traits to enforce policies (e.g., only plugins with handles_phi can receive PHI-containing events) and to toggle features. Plugins declare their traits in the manifest, and core attaches them to the plugin’s identity at runtime.
Transformer	A function or mapping that converts data between a plugin’s internal model and the canonical model. Transformers allow plugins to emit or consume canonical events by translating to their local representation and vice versa. The SDK provides utilities to register transformers, and the core uses them to route and convert messages appropriately. For example, a transformer might convert a plugin’s User object to the platform’s CanonicalUser.v2 schema.
Agent (AI Developer)	In this context, an AI-based assistant that contributes to the codebase following AGENTS.md guidelines. Agents can write code, tests, and docs in automated fashion, but must obey guardrails: use short relevant context, run tests, and go through CI via PRs rather than pushing directly. Agents accelerate development but operate under the same checks and balances as human devs (reviews, CI, etc.).
Docs-Autopilot	A tool that analyzes code changes and proposes documentation updates automatically
GitHub
. It can generate a checklist of needed doc changes or even draft the changes using an LLM. In our pipeline, we use it to keep the /docs in sync with code on the mkdocs branch, by generating PRs whenever development updates
GitHub
.
mike	An extension for MkDocs that manages versioned documentation. It allows deploying multiple versions of docs (e.g., documentation for v1.0, v1.1, etc.) to GitHub Pages simultaneously and handling aliases like "latest". This helps maintain docs for old versions even as new releases happen.
Buf	A CLI tool for protobuf that we use to lint, validate, and generate code from our .proto schemas. Buf ensures we don’t break proto contracts inadvertently and streamlines multi-language codegen with a single command
buf.build
buf.build
.
Cookiecutter Template	A skeleton project template for rapidly creating new components (like a new plugin repository inside our monorepo). It asks for basic info (name, etc.) and lays out the files so the new plugin adheres to Vivified’s standards (manifest, Dockerfile, CI config, etc.). Saves time and prevents mistakes when starting a new plugin.

This blueprint serves as a comprehensive bootstrap guide for Vivified’s repository and system setup. It balances a deterministic structure (clear rules, fixed paths, and automated checks) with room for creative autonomy (plugins can be in any language, agents can propose changes freely within the guardrails). Following these guidelines will ensure the platform’s foundation is solid, consistent, and scalable – paving the way for both human and AI contributors to safely and efficiently collaborate on the Vivified enterprise modular platform.