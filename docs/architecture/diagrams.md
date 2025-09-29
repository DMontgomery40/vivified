# Architecture Diagrams

System architecture diagrams and flow charts. See also: [Three-Lane Model](../core/three-lanes.md).

## Three-Lane Overview

```mermaid
flowchart TB
  %% Three-Lane overview with wrapped labels
  classDef box fill:#eef5ff,stroke:#4c6ef5,color:#222,stroke-width:1px

  subgraph Plugin[Plugin Container\n(no outbound network)]
    P1["LLM Plugin\nclassify=PHI\ntrace_id=...\nrefs not raw PHI"]:::box
  end

  CoreGW["Core Gateway\n(Operator RPC)"]:::box
  Canonical["Canonical Engine\n(schema + policy + audit)"]:::box
  Proxy["Core Proxy\n(allowlist + TLS + secrets)"]:::box
  Vectorizer["Vectorizer Plugin\n(Embed op)"]:::box

  P1 -- "Operator: Embed" --> CoreGW
  CoreGW -- "dispatch" --> Vectorizer
  P1 -- "Canonical: DocumentSummarized" --> Canonical
  P1 -- "Proxy: chat completions" --> Proxy

  class P1,CoreGW,Canonical,Proxy,Vectorizer box
```

## Defaults and Fallbacks

```mermaid
flowchart TB
  %% Default backends and fail-safe fallbacks
  classDef box fill:#f4fff4,stroke:#2e7d32,color:#222,stroke-width:1px
  classDef warn fill:#fff8e1,stroke:#f9a825,color:#222,stroke-width:1px

  subgraph Core[Core Services]
    DB[(Postgres\npostgresql+asyncpg)]:::box
    RAG[(Redis\nredis://localhost:6379/0)]:::box
  end

  subgraph Fallbacks[Graceful Fallbacks]
    MemDB[(SQLite in-tests\nTEST_DB_URL or in-memory)]:::warn
    MemRAG[(In-memory RAG\nif Redis unreachable)]:::warn
  end

  Core --> Fallbacks
  DB -. tests only .-> MemDB
  RAG -. on failure .-> MemRAG
```
