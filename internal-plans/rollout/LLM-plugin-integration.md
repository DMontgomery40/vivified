Integrating an LLM-Powered Assistant (with RAG) into Vivified
Requirements and Goals

We need to add a Conversational AI Assistant to Vivified that can help administrators and power users configure and use the platform. This assistant should leverage LLM (Large Language Model) capabilities, enhanced by Retrieval-Augmented Generation (RAG) to stay up-to-date with Vivified’s plugins and configurations. Key requirements include:

Interactive Q&A and Guidance: The assistant can answer questions like “How do I automatically notify an employee when their expense is approved?” and guide or even perform multi-step configurations. It should serve as a “co-pilot” for Vivified, explaining features or setting them up on request.

Dynamic Knowledge Base (RAG): The assistant’s knowledge must continuously update as the system evolves. If the user installs new plugins (e.g. a QuickBooks integration or an HR module), the assistant’s knowledge base should incorporate those plugins’ capabilities by the next day (or on-demand) so it can answer questions about them.

Multiple LLM Backend Support: It should work with OpenAI API (via an API key) and also easily support on-premise or local LLMs (e.g. through vLLM, Ollama, LMStudio, etc.). This ensures flexibility – users can choose a cloud LLM or a locally hosted model for privacy.

Plugin Architecture Compliance: The LLM assistant should be implemented as a Vivified plugin (to enforce modularity and security), even if shipped with the core by default. We want to dogfood the plugin system: as if this assistant were developed externally and simply plugged in via a manifest. In practice, since it’s a critical feature, it will ship with the core installation (enabled or installed by default), but it must follow the plugin model (with its own manifest, sandboxing, trait declarations, etc.).

Security, RBAC/TBAC Controls: Access to the assistant and its actions must be gated by Vivified’s trait-based and role-based access controls. Users must explicitly enable it and grant it permission to certain scopes. For example, the assistant should only operate if the organization/admin has allowed AI features (opt-in), and it should obey trait restrictions (e.g. not expose sensitive PHI data to an external model if not allowed)
GitHub
GitHub
. We also need to audit its usage and possibly filter its outputs for compliance
GitHub
.

Minimal Performance/Footprint Impact: By default the assistant can be dormant (with an empty knowledge base and no model loaded) until configured. Shipping it adds minimal overhead – if unused, it shouldn’t consume many resources. Enabling it will require building the index (RAG database) and possibly loading a model or making API calls, which should be done efficiently (e.g. asynchronous background jobs for indexing, caching results, etc.).

User Experience: Provide a convenient UI – likely a chat widget in the admin console (e.g. a “Chat with Vivified Assistant” bubble in a corner) and an optional full-page chat interface for longer interactions. The assistant should answer in natural language, possibly with references to documentation if helpful, and be able to perform actions with confirmation. The UI should also allow turning the assistant on/off easily (and indicate if it’s disabled).

Design Overview

Plugin vs Core Placement: Although we initially considered making this a completely separate plugin repository, we’ve decided the AI assistant is essential enough to include in the core distribution. However, it will be structured like a plugin internally. This means defining a Plugin Manifest (JSON) for the assistant, declaring its capabilities, traits, allowed domains, etc. Vivified’s plugin architecture was designed such that dropping a manifest in place should let the core auto-register the plugin
GitHub
. We will test that by treating our assistant as an external plugin package (even if it lives in plugins/assistant/ within the monorepo or a built-in plugin folder).

Registration: On startup, the Plugin Manager should load the assistant’s manifest and register it like any other plugin
GitHub
GitHub
. If the manifest and plugin code are packaged with core, this may happen automatically during core initialization.

Toggling & Permissions: The assistant plugin can be disabled or uninstalled by an admin if desired. We’ll provide a toggle in the Admin UI to enable/disable the AI assistant globally. Also, we will introduce a UI trait for the assistant (e.g. ui.assistant) so that only authorized users (with a certain role/trait) see and can use the chat interface. Likely only admins or specific roles (like “developer” or a new “assistant_user” trait) will have access by default, to avoid general end-users interacting with it without oversight. The trait system will hide the UI for unauthorized users
GitHub
.

Traits and Security: In the manifest, we will declare traits such as:

A security trait like "external_service" for the plugin if it will call external APIs (OpenAI)
GitHub
. The core’s policy engine uses this to enforce data handling rules (e.g. blocking PHI from being sent out)
GitHub
. We might also add a custom trait, e.g. "uses_ai_model", to flag that this plugin connects to an LLM service.

Perhaps a trait requirement that only certain user traits can invoke it. For example, the plugin might require the user context to have admin or developer trait to execute certain operations.

Allowed Domains: The manifest will include an allowed_domains list that whitelists the external endpoints the assistant can reach
GitHub
. For OpenAI usage, we’ll add the OpenAI API domain (and any necessary endpoints) here. This ensures Vivified’s proxy/policy layer will allow the outbound call. If using a local model with no external call, we can omit external domains.

Manifest Example: A rough sketch of assistant/manifest.json:

{
  "id": "vivified-assistant",
  "name": "Vivified AI Assistant",
  "version": "1.0.0",
  "description": "Conversational assistant providing help and automation within Vivified.",
  "contracts": [], 
  "traits": ["external_service"], 
  "dependencies": [],
  "allowed_domains": ["api.openai.com"], 
  "endpoints": {
     "chat": "/assistant/chat" 
  },
  "security": {
    "authentication_required": true,
    "data_classification": ["internal"]
  },
  "compliance": {
    "hipaa_controls": [], 
    "audit_level": "full"
  }
}


This declares the assistant plugin, marking it as an external service. We define an API endpoint /assistant/chat that the plugin will expose (where the frontend can send user questions). We also set audit_level to “full” meaning all interactions should be logged. (The actual manifest schema might differ, but it will follow the format validated by manifest_schema.json
GitHub
.)

Core Integration: We will integrate the assistant into the core Admin API and UI:

Backend: Likely implement a new FastAPI router or endpoints under /assistant (or integrate into the existing admin router) that forward requests to the assistant plugin’s logic. Since the assistant is packaged with core code, it may just be a module we import. If it were truly separate (in another container), we’d use the Operator RPC mechanism to call it, but given it’s core, direct function calls or internal API calls can be used. Still, we might simulate the plugin call via the GatewayService to remain consistent with how external plugins would be invoked
GitHub
.

Frontend: Add a React component for the chat UI (e.g. a small chat window component). This component will call the backend (the /assistant/chat endpoint) with the user’s question and display the answer. We’ll also incorporate it in the navigation – possibly a floating button or an “Assistant” item in the menu (only visible if enabled and user has permission, as controlled by traits from the /admin/plugins or features data
GitHub
).

LLM Assistant Architecture

We will implement the assistant’s brain using LangGraph, which by mid-2025 has become the preferred framework for building complex LLM agents (over the older LangChain)
xenoss.io
. LangGraph allows us to define an agent as a graph of tools and reasoning steps, which is ideal for our needs since the assistant may require multi-step reasoning (search knowledge, then answer, or take actions).

Why LangGraph: LangGraph is purpose-built for stateful, multi-tool agent workflows, offering durability (state persistence), branching logic, and better debugging for agent decisions
xenoss.io
. LangChain’s own documentation suggests using LangGraph for complex agent scenarios to leverage these advanced features
xenoss.io
. In our case, if the assistant needs to perform multi-step operations (e.g. read documentation, then call an internal API, then confirm with user), LangGraph will handle that more reliably than simplistic chain calls.

Agent Tools and Workflow: We will create a ReAct-style agent using LangGraph’s prebuilt components. The agent will be configured with a set of tools (functions) it can use during conversation:

Knowledge Base Search Tool: This tool will implement RAG. It takes a query (the user’s question or a follow-up) and searches the indexed knowledge base (more on that in the RAG section below). The tool will return the most relevant document snippets or facts as a string. This allows the LLM to fetch up-to-date info about Vivified’s plugins, configuration steps, or APIs when formulating an answer.

Vivified Action Tool(s): These are functions that allow the agent to perform operations on the Vivified system. For example, if the user asks to set up an automated alert, and if Vivified has an API to create a workflow or notification rule, we can expose a tool like create_notification(to_user, message, trigger) or a more general call_api(endpoint, payload) that lets the agent invoke Vivified’s internal API (with appropriate checks). Initially, since automated actions can be sensitive, we might start with read-only or advisory tools. But we plan for the agent to eventually do things like create config entries or enable plugins on behalf of the user.

Multi-step Process: If a request requires multiple steps, the agent can break it down. For instance, it might first query the knowledge base (“how to send alerts on expense approved?”), find that the QuickBooks plugin emits an ExpenseApproved event and the Notification plugin can send emails, then form a plan: “create a workflow that on ExpenseApproved event calls Notification.sendEmail”. If an API or scripting interface exists, the agent could attempt to call it. Otherwise, it will respond with step-by-step instructions for the user to implement.

We will utilize LangGraph’s ability to have the LLM reason and decide which tool to use next. If the agent decides to execute a potentially system-changing action, we will build in a confirmation step. For example, the agent might output: “I can set that up for you. Shall I proceed to create the rule?” – and only upon explicit user approval (e.g. the user clicking “Yes”) will we invoke the actual tool function.

Fallback / Calculator / Other Tools: Optionally, we could include simple tools like a calculator or date function if needed, but these are less critical for our domain. The primary tools are the two above (knowledge retrieval and internal actions).

Memory and Context: For the conversation itself, we will maintain the dialogue context. LangGraph supports persistent memory stores if needed (e.g. storing conversation state or long-term facts)
xenoss.io
. Initially, a short-term memory (the recent conversation) is sufficient. The agent’s prompts will be designed with Vivified’s context in mind (“You are a helpful assistant for the Vivified platform...”). We’ll include instructions that if the user asks to perform an action, the agent must verify permissions and possibly ask for confirmation, etc., to incorporate our security guardrails into the prompt.

LLM Model Choices: We will not hard-code to a single model. Instead, the agent will be parameterized to use whichever model is configured:

For OpenAI, LangGraph can use an OpenAI chat model by specifying something like model="openai:gpt-4-0613" or similar (assuming LangGraph uses LangChain’s model naming conventions).

For local models, we might run an API that mimics OpenAI (some local model servers do this), or use LangGraph’s integration with HuggingFace transformers. We’ll design the code to easily switch between a remote API call vs local inference.

The default will likely be OpenAI GPT-4 or GPT-3.5 (accessible via API key in config) because of its reliability and capability. But we will document how to plug in a local model (for example, point the assistant to a local endpoint like http://localhost:8000/v1/chat that serves a Vicuna or Llama2 model via something like vLLM or Ollama).

Example Flow:

User (Admin) opens the chat and asks: “How do I automatically notify an employee that their expense report was approved?”

The assistant agent receives this query. It does not have the answer verbatim, so it calls the Knowledge Base Search tool with a query like “expense approved event notify employee how to automate”.

The search tool retrieves, say, a snippet from the QuickBooks Plugin documentation about an ExpenseApproved event and a snippet from the Notification Plugin docs about sending messages.

The agent’s LLM reads these snippets (embedding them in its prompt) and formulates an answer: it might outline the solution (e.g. “You can create an automation: when QuickBooks plugin fires an ExpenseApproved event, have the Notification plugin send an alert to the employee. To do this, enable the Workflow plugin and configure a rule…”).

If capable, the agent might then attempt an action: perhaps calling createWorkflowRule("ExpenseApproved", action=SendAlert(...)) via an internal API. If we have that tool and the user has permitted automated changes, it will call it. Otherwise, it stops at giving instructions.

The user can then follow the instructions or confirm execution if prompted.

All these steps and any API calls are logged for auditing.

Retrieval-Augmented Generation (RAG) Implementation

A core component is the Knowledge Base that the assistant will query. We will implement RAG as follows:

Document Corpus: The knowledge base will include:

Vivified Documentation: Any official documentation we have (likely the Markdown files under docs/ or content from the Vivified user guide) about features, configuration, plugins, etc. This provides general knowledge. We may also include relevant parts of the internal plans if they contain useful info that is also user-facing.

Plugin manifests and docs: For each installed plugin (especially third-party or optional ones the user adds), we include its manifest data (name, description, declared endpoints/events) and any README or help text that comes with it. If the plugin has a documentation page in the Vivified docs site (for example, “QuickBooks Plugin – Setup and Usage”), that should be added. Essentially, when a new plugin is added, the assistant should ingest whatever documentation is available about that plugin. We might enforce that plugin developers provide a short usage guide that we can index.

Configuration/Usage data? We must be careful not to include sensitive user data in the knowledge base. We will focus on static reference info (docs, manifests). However, some configuration metadata might be useful – e.g., knowing which plugins are currently enabled. The assistant could have access to a list of active plugins and their basic config (non-sensitive parts) so it knows what tools are available in the user’s deployment. (For instance, it should know if the Notification plugin is present before suggesting using it.)

We will not include actual user-specific data (like actual expense records or PHI) in the knowledge index – that’s beyond scope and a privacy risk. The assistant is about how to use the system, not the data within the system.

Embedding & Indexing: We will use vector embeddings to index these documents for semantic search. Likely steps:

Split documents into chunks (e.g. by paragraphs or sections).

Compute embeddings for each chunk. If using OpenAI, we could use the OpenAI Embedding API (e.g. text-embedding-ada-002). If we prefer a local approach, we can use a model like SentenceTransformer or InstructorXL to embed.

Store the embeddings in a vector store. We noted that Vivified already uses Redis (for event bus or caching), so we can leverage Redis with RediSearch module to store vectors and perform similarity search. This avoids adding another database and fits with existing infra
GitHub
. Alternatively, if a Postgres is in use with pgvector, that’s another option. But Redis is a good choice here for quick retrieval (and it keeps everything in-memory for fast access).

We’ll maintain metadata with each vector (like which plugin or doc it came from, so we can potentially filter by trait – e.g. if a piece of info is marked internal vs public).

Index Update Triggers: The knowledge base should update regularly and when changes occur:

On startup of the assistant (or daily at off-peak hours), run a job to rebuild or update the index. If new plugins were installed or docs updated, pick those up.

On demand: possibly provide an “Update knowledge base” button for admins, so after they install a new plugin or make a major change, they can manually trigger re-indexing immediately.

On plugin install events: We can hook into the plugin registry – when a new plugin registers, schedule an immediate embedding of its manifest/docs.

The process of updating will likely run asynchronously (in a background thread or task queue) so as not to block the main app.

Because the knowledge base can grow, we might implement incremental indexing (only add new docs) and maybe prune old or irrelevant info periodically.

Search Tool Implementation: The “search knowledge” tool in the agent will:

Accept a query string.

Embed the query using the same embedding model.

Query the vector store for top N similar chunks.

Return those chunks (likely concatenated or as a list). We’ll need to format these for the LLM – possibly as quoted context or an “openAI function” result. But simplest is to feed them into the prompt as context (e.g. “According to the documentation: [snippet] ... [snippet]. Answer the question…”).

We should also possibly return source identifiers with the text, so the assistant can cite which plugin or doc the info came from, when responding. (This could help it be more factual and also allows us to present citations in the UI if desired).

Scope and Filtering: Administrators may want control over what the assistant can see. For example, there might be documents or plugin details they consider sensitive. We will respect Vivified’s trait-based data classification:

If a document is classified as confidential or PHI (unlikely for general docs, but just in case), we could tag its vectors accordingly (e.g. data_traits like in events). The assistant plugin, being marked as an external service, might be forbidden to retrieve PHI-tagged content by the policy engine
GitHub
. In practice, most of our knowledge base will be product documentation, which is not sensitive, so this may not be a big issue. But we will design with the idea that certain content could be excluded if the company policy says “AI assistants cannot access X”.

We’ll allow the admin to configure which categories of docs to include. For example, maybe a setting: “Include internal admin guides in assistant knowledge (yes/no)”. If set no, we don’t index those.

Size Considerations: Initially, the volume of docs + manifests should be manageable (likely a few MB of text). Redis can easily handle this in memory. If it grows, we may consider chunking by topic and retrieving hierarchically. But for now, a straightforward top-N similarity search with a well-chosen N (like top 5) should suffice to give good context to the LLM.

LLM Backend Flexibility

One design goal is to support both cloud-based and local LLM deployments:

OpenAI Support: We will integrate OpenAI first (since it’s widely used and we can leverage high-quality models like GPT-4). The user will provide their API key (and possibly choose model) in the Vivified configuration (likely via a settings page or an environment variable for the assistant plugin). We’ll store this securely (as a secret in config service). When the assistant plugin calls OpenAI, it will do so through the allowed domain (as per manifest) and with TLS, etc. We should also enable streaming responses for a better UI experience (OpenAI API can stream tokens; we’d propagate that to the frontend for a live typing effect).

Azure OpenAI: If needed for some enterprise users, we can allow endpoint and key configuration for Azure’s flavor of OpenAI as well. This is just a minor variation (different API base URL, etc).

Local Model via API: For on-prem users, one straightforward way is to run a local LLM server that provides a similar API. For example:

vLLM – an open source project that serves models efficiently with an API compatible with OpenAI’s format. A user could run vLLM with a Llama-2 or GPT-J model on their hardware, and point the assistant to http://<vllm-server>/v1/chat/completions. We’ll make the base URL configurable so this is possible.

Ollama – if the user is on Mac or has Ollama, they could use that. Ollama has a CLI/API but not exactly OpenAI format; however, we might not integrate directly unless demand is high. We can document how to use our generic local endpoint config for it.

HuggingFace Transformers locally – as a last resort, we could allow the assistant plugin to load a model in-process using HuggingFace (like running a smaller model within the plugin’s Python process). This would avoid network calls altogether. The downside is large memory usage in the core process or plugin container, and possibly slower performance if the model is big and no GPU. Given this complexity, our initial approach will be to rely on an external server if a local model is desired. That way the heavy model stays in its own process (which aligns with our plugin isolation philosophy – the model runtime could even be another plugin or service).

Model/Provider Abstraction: We’ll create a small Python class or config in the assistant plugin like LLMBackend with methods generate(prompt) and embed(text) that encapsulates whether it’s calling OpenAI or a local service. This makes it easy to add providers. We’ll use the OpenAI mode if an API key is present; if not, perhaps fall back to a local default model (if configured).

Testing with Smaller Models: For dev/testing (and CI if needed), we might use a smaller model like GPT-3.5 or even a dummy LLM. We could default to GPT-3.5-turbo for faster, cheaper responses and then let the user select GPT-4 if they have the quota. All such options will be exposed in the config (maybe an “AI Settings” page in the admin UI, per the Vivified plan which suggested an AI config section
GitHub
).

LangGraph Compatibility: LangGraph supports multiple providers. We saw an example with an Anthropic model
github.com
. We will ensure our chosen approach is compatible – likely by using LangChain under the hood, which LangGraph can piggyback on. If needed, we may directly call the API in our tool functions instead of having LangGraph manage it; but ideally, we use LangGraph’s create_react_agent(model=..., tools=[...]) so that the heavy lifting of LLM invocation is handled by the framework. LangGraph’s documentation indicates it supports async and various model backends (requiring Python 3.11+ which we likely use)
xenoss.io
.

Concurrent Usage and Rate Limits: Because multiple admins might chat or multiple questions asked in succession, we should handle concurrency. If using OpenAI, we must respect rate limits (maybe implement exponential backoff or queue requests if needed). For local models, concurrency might be limited by hardware. We can initially keep it simple (the FastAPI endpoint for chat can be called concurrently; we rely on the LLM backend to queue if needed). Optionally, we set a limit like one session at a time if using a heavy local model to avoid overload.

No Model “Inside” Vivified by Default: Importantly, we are not bundling a specific AI model in the Vivified installation – that would be heavy and raise distribution issues. Instead, we ship the integration and the empty index; the actual model (OpenAI or other) is pulled in when configured by the user. This aligns with keeping the core lightweight. The documentation will clearly state that the assistant won’t function until you provide an API key or set up a model, and walk through those steps in the setup wizard.

Security, Compliance, and Access Control

Because this feature involves AI and potentially powerful actions, we must build with security and compliance from the start. Vivified’s architecture is very security-conscious (HIPAA/SOC2 concerns, etc.), so our assistant follows suit:

Opt-In & Trait Enforcement: The assistant will be disabled by default (or at least, require explicit enabling during setup). In the Setup Wizard for Vivified, we’ll add a step “Do you want to enable the AI Assistant?” If the user says yes, we then prompt for an OpenAI key or local model setup. If no, the feature stays off (no model calls, no indexing of possibly sensitive docs). Even after enabling, we can require that only users with an “AI Allowed” trait can invoke it. Perhaps we introduce a trait like ai_user or reuse an existing high-level trait (maybe admin covers it). This prevents a scenario where a lower-privilege user tries to use the assistant to gain knowledge or perform actions they shouldn’t. The core will check the user’s traits each time the assistant endpoint is called, and return 403 if not allowed.

Trait-Based Data Restriction: Marking the plugin as external_service means the policy engine knows it sends data out of the system
GitHub
. The policy engine can sanitize or block certain data flows to it. For example, if some plugin tried to send an event containing PHI to the assistant plugin, the policy might block it (similar to how Faxbot had rules to prevent PHI leaving certain boundaries
GitHub
). In our case, we mostly send documentation text to the LLM – which should not contain actual PHI or PII, just product info. But if there were any chance user data made it in (say an admin asks “What is patient John Doe’s status?” – ideally the assistant should not answer since that’s not in docs anyway), we will avoid that. We will implement content filters on the assistant: if a user query appears to request sensitive data or if the answer may include sensitive info from the knowledge base, we either refuse or mask it. This aligns with Vivified’s mention of “AI/LLM services with security filters” as part of its guardrails
GitHub
.

No Training on Sensitive Data: We are only using the LLM in inference mode, on specific prompt context – not training it on customer data. So data exposure is limited to the prompt and retrieved docs per query. We will document that the assistant may send snippets of Vivified docs or plugin info to the LLM API. If using OpenAI, that data goes to OpenAI’s servers (which some organizations might disallow). Thus, the decision to enable the assistant (especially with a cloud API) is a trust decision. We will provide an option to restrict certain content from being sent. For example, maybe mark some internal docs as “do not send to external AI”. The trait mechanism can support that by tagging documents and having the assistant check traits before including them in a prompt.

Auditing and Logging: Every interaction with the assistant should be logged as an audit event. We will log the user ID, timestamp, question asked, and whether any actions were taken (and what). The actual content of the question/answer can be logged to an audit trail (this might be sensitive, but for an admin assistant maybe acceptable; we could mask certain parts if needed). Audit logs ensure administrators can review what the AI is being asked to do
GitHub
. For instance, if the assistant was used to change a configuration, there will be an audit record like “AI_ASSISTANT executed action X on behalf of Admin Y at time Z”. This is crucial for compliance (and debugging if the AI does something unexpected).

Rate Limiting & Misuse Prevention: We may implement a basic rate limit on the assistant’s endpoint to avoid abuse or runaway costs (e.g. don’t let someone script 1000 questions to GPT-4). Maybe something like no more than e.g. 5 queries per minute per user, configurable. Also, if using an external API, handle errors like rate limit responses gracefully (tell the user to slow down).

Output Filtering: We will use OpenAI’s function calling or our own parsing to ensure the assistant’s outputs that involve actions are valid. LangGraph agents can be made to output structured data which we can validate. If the assistant returns a plan or action, we intercept it before execution and check it against policies. Additionally, we might want to filter the natural language answer for any compliance issues (e.g. it shouldn’t reveal internal secrets or encourage insecure practices). We can run the answer through a simple profanity or PII scanner just in case, though since its knowledge is mostly docs, this is low risk.

Deletion and Data Retention: If the assistant is disabled or uninstalled, we should allow the admin to also wipe its knowledge index (e.g. remove vectors from Redis) in case they worry about cached info. We’ll provide a “Delete AI index” button on uninstall to purge any stored embeddings (which are anyway just transforms of documentation, but for completeness).

Plugin Isolation: If we ended up running the assistant as a separate container (in a future scenario), it would be heavily sandboxed. Currently, since it’s core, it runs in-process. But we still logically isolate it: it will use only official interfaces to do things (i.e. call core APIs, not directly poke at the database or files). This keeps it consistent with the plugin lane model: even though internal, it should act as if it’s another service using the Operator lane for any core modifications
GitHub
. This ensures all permission checks are applied consistently.

UI Integration

We will integrate the assistant into the Admin Console in a user-friendly way:

Chat Widget: A small chat bubble or icon in the bottom-right corner of the admin UI that, when clicked, pops up a chat window. This window will show the conversation with the assistant (messages from user and responses from AI). We’ll use a UI library or custom MUI components to make it overlay nicely. Think of how Intercom or ChatGPT’s web UI looks in compact form.

Full Page (Console) View: For extended use or for certain roles, we might also have a dedicated page (e.g. “Assistant” in the nav) where the chat is full-screen, possibly with additional context or controls (like a history of past queries, or settings to refine the query like “search in plugin X only”). The user in the prompt asked if it should have its own page – the answer was yes, after the quick access widget, a full page is useful for longer sessions and for controlling access by role.

Trait-based Display: The frontend will use the trait info from the backend to decide if the assistant UI is shown. For example, if the current user lacks the assistant_user permission, we simply won’t render the chat icon. This prevents unauthorized use (defense in depth, since backend also checks).

Onboarding and Tips: The first time a user opens the assistant, it might show a brief note about what it can do (“Hi! I can answer questions about Vivified and help set things up. Ask me anything about the configuration or say ‘help’ to see examples.”). Possibly provide a few example prompts.

Conversation Persistence: We can keep the conversation state in the UI (React state) per session. We might not (at least initially) store long-term history on the server (to avoid storing potentially sensitive Q&A). Each new browser session may start a fresh convo. Later, we could allow viewing past Q&As or saving solutions, but not a priority now.

Executing Actions via UI: If the assistant’s answer includes an action (like “Shall I create this rule now?”), we need UI elements for the user to confirm or cancel. For instance, the assistant’s message could be rendered with a “Confirm” and “Cancel” button if an action is pending. Behind the scenes, we would treat confirmation as sending a hidden message to the agent like “User confirmed action X” so the agent can proceed to call the tool. Alternatively, our backend might pause awaiting user input. This will require some state management in the agent (LangGraph supports human-in-the-loop interrupts for this scenario
xenoss.io
). We’ll utilize that: basically mark that a checkpoint was reached and wait until user triggers continuation.

Loading Indicators & Errors: When user sends a query, show a spinner or “Assistant is thinking…” message. If the backend times out or error (e.g. OpenAI fails), show an error message gracefully (“I’m sorry, I ran into an error processing that request.”). Also handle if the knowledge base is empty or the assistant is disabled (e.g. “Assistant is not enabled” message).

Admin Page for AI Settings: Under settings, have a section for “AI Assistant” where:

Admin can toggle it on/off.

Provide the OpenAI API key or select “Use local model” and provide the URL or model name.

Set preferences like which documents to include in index, and a button to rebuild index now.

Possibly view usage statistics (how many queries made, tokens used, cost estimation if OpenAI).

This gives transparency and control. It implements what was hinted in internal docs: “Admin UI has a section for AI settings (enabling features, monitoring usage)”
GitHub
.

Visual Indicator of AI Proposals: If the assistant sets something up automatically, we might highlight it in the UI (for example, if it created a new rule in the Workflow plugin, that rule could have a tag “created by AI assistant” so the admin knows).

Avoid Annoyance: The user specifically said having it in the corner could get annoying after one question, hence the separate page. So we’ll ensure the widget can be minimized or closed easily, and it doesn’t nag the user. Possibly it could show an unread badge if it has an answer and the user navigated away, but nothing intrusive.

Implementation Plan (Step-by-Step)

To realize this, we will proceed with the following high-level steps:

Update Monorepo Structure: Ensure there is a place for the assistant plugin code. Since the blueprint suggests a plugins/ directory in the monorepo
GitHub
, we can create plugins/assistant/ for our plugin. Inside, have manifest.json, and implementation code (could be Python if we integrate it with core directly).

Define Manifest & Schema: Write the manifest.json for the assistant as discussed, including appropriate traits and allowed_domains. Use the CLI’s validate-manifest to confirm it meets the schema
GitHub
. Update the manifest if needed (e.g. ensure no conflicting traits, etc.).

Core Plugin Registry Integration: Modify core startup to auto-register the assistant plugin. Possibly, we call registry.register_plugin() with the manifest at startup (if the plugin isn’t dynamically discovered). Or we place the manifest in a known folder that core scans. Vivified might already scan plugins/*/manifest.json on startup – if so, simply ensure our assistant’s manifest is in that path. We’ll verify plugin registration flow works (the notification plugin test suggests manual wiring was done; we want to avoid that by using the general mechanism).

Backend Implementation: Develop the assistant plugin’s Python module:

Use FastAPI or dependency injection to create a route (e.g. @admin_router.post("/assistant/chat")) that accepts a request containing user query (and possibly conversation context or an action confirmation).

In the handler, authenticate the user (it’s behind auth already via require_auth probably) and verify the user’s traits for permission.

Initialize or use a singleton instance of the LangGraph agent. We might keep an agent in memory for the session or recreate per call (but that could be slower, so maybe keep one agent with short-term memory).

If the request is a new question: call agent.invoke() with the user message. This will internally use the tools (one of which calls our vector store, etc.). Gather the agent’s response.

If the request is a continuation (confirmation): signal the agent to continue the flow (LangGraph might allow storing the partial state awaiting input).

Return the assistant’s answer (and any action results) as JSON.

Handle streaming if possible: For OpenAI, we might stream tokens. LangGraph can handle streaming outputs; if not, we may just get the final text and stream it chunk by chunk to the frontend via Server-Sent Events or WebSocket. This might be a nice-to-have; if time is short, we can just return the full answer text.

Vector Store Setup: Install and configure Redis with RediSearch (if not already). In the assistant plugin, write code to connect to Redis (or the core’s Redis instance) and create an index for docs (with vector type). Alternatively, use an in-memory FAISS index for simplicity, but Redis is preferred for persistence and multi-process use.

Write an indexing function that goes through docs and plugin manifests, computes embeddings, and upserts them into the index. Use an embedding model: e.g. call OpenAI embedding API (if key provided) for each chunk. If no external key, use a local embedding model (maybe a small sentence-transformer loaded at runtime – which could be an additional dependency, but we can include one).

Store metadata with each vector (like source: "QuickBooks Plugin Docs", chunk_id: 5 etc.).

This function can be triggered via a CLI command or an API call. We might integrate it with the “AI settings” page actions (e.g. a button triggers a POST to an endpoint that runs this job). Also integrate with plugin install events (perhaps call it at the end of plugin registration for the new plugin’s docs only).

LangGraph Agent Setup: Add the langgraph dependency to our project (update requirements.txt). Construct the agent with:

LLM: depending on config (OpenAI or local).

Tools: define Python functions for search_knowledge(query) and any needed action functions. Register these with the agent (LangGraph’s create_react_agent takes a list of tools). Ensure each tool has a docstring for the LLM to know what it does.

Prompt: a system prompt that includes instructions about Vivified and how to use the tools. E.g. “You are Vivified’s assistant. You have access to: a knowledge base tool (search_docs) that gives documentation snippets, and potentially an action tool to perform tasks when explicitly approved. Always follow compliance: do not reveal sensitive data. If you plan to make a change, ask for confirmation,” etc.

Memory: decide if we track conversation. Possibly we use LangGraph’s memory to keep the last few interactions so it remembers context in multi-turn dialogues.

Test the agent in isolation with a couple of sample questions to fine-tune prompt and ensure it uses the tools appropriately.

Frontend Implementation: In core/admin_ui (React app):

Create a component AssistantChat.tsx with state for messages. Use MUI components for chat bubbles.

Add an icon (maybe a question mark or chat icon) in a fixed position that toggles the chat window.

Chat window: shows a scrollable history and an input box.

On sending a message, call the backend (POST /assistant/chat) with the message. Display the user message optimistically in UI, then await response.

Display typing indicator while waiting. Once response arrives, add it to the chat.

If response payload indicates an action confirmation is needed, render the Confirm/Cancel buttons along with the assistant’s message. If user clicks Confirm, send a follow-up to backend (we might include something like {"confirm": true, "action": "<action_id>"} so the agent knows to proceed, or simply send the same question with a tag that user confirmed).

Make sure to handle error states (show error message if request fails).

Hook this component into the main App. Possibly include it globally (since it might overlay any page). Ensure to respect ui.assistant trait: perhaps the /admin/plugins API will list installed plugins and we see if vivified-assistant is in the list and enabled for this user. We could also have an endpoint /assistant/status that gives availability. But simplest is: if the plugin is enabled and user is admin, show it.

Also create a settings UI under an “AI Assistant” section (maybe as part of an Admin Settings page). This would allow input of API key (if not set via env, we can save it via config service), a dropdown for model (GPT3.5 vs GPT4 vs custom endpoint), and a button to reindex. This page will call corresponding admin API endpoints (we might add to admin_router something like /admin/assistant/config and /admin/assistant/reindex).

Testing & Iteration:

Write unit tests for the assistant backend: test that a sample question flows through: the search tool returns expected docs (we can inject a fake vector store for test), and the agent produces a reasonable answer (we might mock the LLM with a stub for determinism in tests, given we can’t call OpenAI in CI). Also test permission enforcement: if user without trait calls the endpoint, it should 403.

Test the end-to-end manually: spin up Vivified with the assistant, ask various questions (some answerable from docs, some requiring multi-step). Adjust the prompt or tools as needed if the agent gives incorrect or unsafe answers.

Specifically test a scenario of action confirmation to ensure our human-in-loop mechanism works with LangGraph (this might be tricky and may require reading LangGraph docs on interrupts).

Security testing: attempt to prompt the assistant to do something disallowed (like “exfiltrate data” or “ignore policies”) and ensure it refuses. The system prompt and trait system should help here, but we remain vigilant.

Performance: test indexing time (if too slow, consider optimizing embedding calls with batching) and the latency of answering (might use streaming to improve perceived speed).

Documentation: Update Vivified’s docs to include a section on the AI Assistant: how to enable it, its limitations, and warnings about external data. Also update any compliance documentation to mention that if enabled, some data is sent to third-party LLMs (unless a local model is used) – so customers can decide accordingly.

Deployment Considerations: If Vivified is deployed via Docker Compose, ensure the Redis instance has RediSearch enabled or use a Redis image with the module. Or consider using a separate vector store container if needed. Also, if using local model, it’s up to user to run that – we just need to support connecting to it. Possibly provide a docker-compose option to run a local LLM container (though that gets into distributing models which is complex; better to let user handle it).

Future Enhancements: Note down future to-dos: e.g. more advanced workflow integration (maybe a dedicated “Workflow plugin” that the assistant can instruct), learning from user behavior, multi-tenant support (if Vivified gets multi-tenant, ensure the assistant’s index is per-tenant and it doesn’t mix data), etc.

Throughout, we keep in mind Vivified’s “AI integration guardrails” principle – AI features are optional and must maintain compliance
GitHub
. By implementing the assistant as described, we prove out the plugin architecture (as requested, we’re effectively “proving them wrong or right” that adding a JSON manifest and plugin can seamlessly extend Vivified). This assistant will be a high-profile example of Vivified’s extensibility and a very useful feature for users, all while respecting the system’s security and modular design.

Conclusion

In summary, we will deliver a Vivified AI Assistant plugin that ships with the core platform but can be enabled or disabled as needed. It uses a LangGraph-based LLM agent to answer questions and perform multi-step tasks, grounded by a continuously updated RAG knowledge base built from Vivified’s own documentation and the user’s installed plugins. It will support both cloud and on-prem LLMs, fitting diverse deployment needs. We will enforce strict trait-based access controls and audit logging around this feature, ensuring it operates within Vivified’s security framework
GitHub
GitHub
. The end result will be a powerful “copilot” for Vivified administrators – making the platform more user-friendly and reducing the learning curve, without compromising on the principles of modularity and compliance that define Vivified.

sources:
GitHub
xenoss.io
GitHub
GitHub
 (All cited plans and references are used to align the design with Vivified’s architectural vision and industry best practices.)