#!/usr/bin/env python3
"""
Enhanced Docs Autopilot for Vivified Platform
Generates comprehensive documentation using OpenAI GPT-4 with full context awareness
"""

from __future__ import annotations

import os
import re
import json
import subprocess
import shlex
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any
import requests
from dataclasses import dataclass


@dataclass
class DocumentationContext:
    """Comprehensive context for documentation generation"""
    
    agents_md: str
    openapi_spec: str
    provider_traits: str
    env_example: str
    core_services: Dict[str, str]
    plugin_manifests: List[str]
    admin_ui_components: List[str]
    security_policies: str
    canonical_models: str
    recent_changes: List[str]
    existing_docs: Dict[str, str]


class EnhancedDocsAutopilot:
    """Enhanced documentation automation with LLM integration"""
    
    def __init__(self, repo_root: Path = None):
        self.repo_root = Path(repo_root or os.getcwd())
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.github_token = os.getenv("GITHUB_TOKEN")
        
        # Content filtering patterns - exclude internal plans and runbooks
        self.exclude_patterns = [
            r"phase\s*\d+",
            r"v\d+\s*(plan|runbook)",
            r"internal[-_]?plan",
            r"TODO[-_]?plan",
            r"migration[-_]?plan",
            r"HIPAA[-_]?audit",
            r"pentest[-_]?results",
            r"security[-_]?scan",
            r"bootstrap[-_]?admin",
            r"dev[-_]?mode[-_]?only",
        ]
        
        # Material for MkDocs features to utilize
        self.material_features = [
            "navigation.instant",
            "navigation.tracking",
            "navigation.tabs",
            "navigation.sections",
            "navigation.expand",
            "navigation.indexes",
            "navigation.top",
            "toc.follow",
            "toc.integrate",
            "content.code.copy",
            "content.code.annotate",
            "content.tabs.link",
            "content.tooltips",
            "search.suggest",
            "search.highlight",
            "search.share",
        ]
        
    def gather_comprehensive_context(self, base_ref: str = None) -> DocumentationContext:
        """Gather comprehensive context from the entire codebase"""
        
        # Get AGENTS.md for high-level understanding
        agents_md = self._read_file(self.repo_root / "AGENTS.md", max_chars=15000)
        agents_md = self._filter_sensitive_content(agents_md)
        
        # Get OpenAPI spec
        openapi_path = self.repo_root / "core" / "gateway" / "openapi.json"
        if not openapi_path.exists():
            openapi_path = self.repo_root / "openapi.json"
        openapi_spec = self._read_file(openapi_path, max_chars=10000)
        
        # Get provider traits
        traits_path = self.repo_root / "config" / "provider_traits.json"
        provider_traits = self._read_file(traits_path, max_chars=5000)
        
        # Get environment example
        env_example = self._read_file(self.repo_root / ".env.example", max_chars=3000)
        env_example = self._sanitize_env_example(env_example)
        
        # Analyze core services
        core_services = self._analyze_core_services()
        
        # Get plugin manifests
        plugin_manifests = self._gather_plugin_manifests()
        
        # Analyze Admin UI components
        admin_ui_components = self._analyze_admin_ui()
        
        # Get security policies
        security_policies = self._gather_security_policies()
        
        # Get canonical models
        canonical_models = self._gather_canonical_models()
        
        # Get recent changes
        recent_changes = self._get_git_changes(base_ref)
        
        # Get existing documentation structure
        existing_docs = self._analyze_existing_docs()
        
        return DocumentationContext(
            agents_md=agents_md,
            openapi_spec=openapi_spec,
            provider_traits=provider_traits,
            env_example=env_example,
            core_services=core_services,
            plugin_manifests=plugin_manifests,
            admin_ui_components=admin_ui_components,
            security_policies=security_policies,
            canonical_models=canonical_models,
            recent_changes=recent_changes,
            existing_docs=existing_docs,
        )
    
    def _read_file(self, path: Path, max_chars: int = 10000) -> str:
        """Read file safely with size limit"""
        try:
            content = path.read_text(encoding="utf-8")
            if len(content) > max_chars:
                content = content[:max_chars] + "\n... [truncated]"
            return content
        except Exception:
            return ""
    
    def _filter_sensitive_content(self, content: str) -> str:
        """Filter out sensitive internal content"""
        lines = content.split('\n')
        filtered_lines = []
        skip_section = False
        
        for line in lines:
            # Check if we should skip this line
            if any(re.search(pattern, line, re.IGNORECASE) for pattern in self.exclude_patterns):
                skip_section = True
                continue
            
            # Reset skip on new major section
            if line.startswith('#') and not line.startswith('####'):
                skip_section = False
            
            if not skip_section:
                # Additional filtering for specific terms
                if not any(term in line.lower() for term in ['bootstrap_admin', 'dev_mode=true', 'phase 1', 'phase 2']):
                    filtered_lines.append(line)
        
        return '\n'.join(filtered_lines)
    
    def _sanitize_env_example(self, content: str) -> str:
        """Sanitize environment example to remove actual secrets"""
        lines = content.split('\n')
        sanitized = []
        for line in lines:
            if '=' in line and not line.startswith('#'):
                key, value = line.split('=', 1)
                # Keep the key but sanitize the value
                if any(secret in key.lower() for secret in ['key', 'secret', 'token', 'password']):
                    sanitized.append(f"{key}=<your-{key.lower().replace('_', '-')}-here>")
                else:
                    sanitized.append(line)
            else:
                sanitized.append(line)
        return '\n'.join(sanitized)
    
    def _analyze_core_services(self) -> Dict[str, str]:
        """Analyze core services structure"""
        services = {}
        core_path = self.repo_root / "core"
        
        if core_path.exists():
            for service_dir in core_path.iterdir():
                if service_dir.is_dir() and not service_dir.name.startswith('_'):
                    readme = service_dir / "README.md"
                    if readme.exists():
                        services[service_dir.name] = self._read_file(readme, max_chars=2000)
                    else:
                        # Try to understand from __init__.py or main module
                        init_file = service_dir / "__init__.py"
                        if init_file.exists():
                            content = self._read_file(init_file, max_chars=1000)
                            # Extract docstrings
                            docstring_match = re.search(r'"""(.*?)"""', content, re.DOTALL)
                            if docstring_match:
                                services[service_dir.name] = docstring_match.group(1)
        
        return services
    
    def _gather_plugin_manifests(self) -> List[str]:
        """Gather plugin manifest information"""
        manifests = []
        plugins_path = self.repo_root / "plugins"
        
        if plugins_path.exists():
            for plugin_dir in plugins_path.iterdir():
                if plugin_dir.is_dir():
                    manifest_path = plugin_dir / "manifest.json"
                    if manifest_path.exists():
                        manifest_content = self._read_file(manifest_path, max_chars=1000)
                        manifests.append(f"## {plugin_dir.name}\n{manifest_content}")
        
        return manifests
    
    def _analyze_admin_ui(self) -> List[str]:
        """Analyze Admin UI components and flows"""
        components = []
        admin_ui_path = self.repo_root / "core" / "admin_ui"
        
        if admin_ui_path.exists():
            # Look for React/Vue components
            for ext in ['tsx', 'jsx', 'vue']:
                for component_file in admin_ui_path.rglob(f"*.{ext}"):
                    rel_path = component_file.relative_to(admin_ui_path)
                    components.append(str(rel_path))
        
        return components[:50]  # Limit to avoid overwhelming the context
    
    def _gather_security_policies(self) -> str:
        """Gather security and policy information"""
        security_content = []
        
        # Look for security-related files
        security_files = [
            "core/policy/README.md",
            "core/identity/README.md",
            "core/audit/README.md",
            "SECURITY.md",
        ]
        
        for file_path in security_files:
            full_path = self.repo_root / file_path
            if full_path.exists():
                content = self._read_file(full_path, max_chars=2000)
                security_content.append(f"### {file_path}\n{content}")
        
        return '\n\n'.join(security_content)
    
    def _gather_canonical_models(self) -> str:
        """Gather canonical model definitions"""
        canonical_content = []
        canonical_path = self.repo_root / "core" / "canonical"
        
        if canonical_path.exists():
            # Look for model definitions
            for model_file in canonical_path.rglob("*.proto"):
                content = self._read_file(model_file, max_chars=1000)
                canonical_content.append(f"### {model_file.name}\n{content}")
            
            for model_file in canonical_path.rglob("*model*.py"):
                content = self._read_file(model_file, max_chars=1000)
                # Extract class definitions
                classes = re.findall(r'class (\w+).*?:\n(.*?)(?=\nclass|\Z)', content, re.DOTALL)
                for class_name, class_body in classes[:5]:  # Limit to 5 classes
                    canonical_content.append(f"### {class_name}\n{class_body[:500]}")
        
        return '\n\n'.join(canonical_content)
    
    def _get_git_changes(self, base_ref: str = None) -> List[str]:
        """Get list of changed files or all files if base_ref is None"""
        try:
            if base_ref is None:
                # Full scan mode - get all tracked files in the repository
                cmd = "git ls-files"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=self.repo_root)
                if result.returncode == 0:
                    all_files = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                    # Filter to only important code files
                    important_extensions = {'.py', '.ts', '.tsx', '.js', '.jsx', '.go', '.proto', '.md', '.yml', '.yaml', '.json'}
                    important_files = []
                    for f in all_files:
                        if any(f.endswith(ext) for ext in important_extensions):
                            # Skip test files and node_modules
                            if 'node_modules' not in f and 'test' not in f.lower() and '__pycache__' not in f:
                                important_files.append(f)
                    print(f"  📂 Found {len(important_files)} important files in repository")
                    return important_files[:500]  # Limit to avoid overwhelming context
            else:
                # Diff mode - get only changed files
                cmd = f"git diff --name-only {shlex.quote(base_ref)}..HEAD"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=self.repo_root)
                if result.returncode == 0:
                    return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except Exception as e:
            print(f"  ⚠️ Error getting file list: {e}")
        return []
    
    def _analyze_existing_docs(self) -> Dict[str, str]:
        """Analyze existing documentation structure"""
        docs = {}
        docs_path = self.repo_root / "docs"
        
        if docs_path.exists():
            for doc_file in docs_path.rglob("*.md"):
                rel_path = doc_file.relative_to(docs_path)
                # Get first 500 chars to understand the document
                content = self._read_file(doc_file, max_chars=500)
                docs[str(rel_path)] = content
        
        return docs
    
    def generate_documentation_with_llm(self, context: DocumentationContext) -> Dict[str, str]:
        """Generate documentation using OpenAI GPT-4"""
        
        if not self.openai_api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")
        
        # Prepare the comprehensive prompt
        system_prompt = self._create_system_prompt()
        user_prompt = self._create_user_prompt(context)
        
        # Call OpenAI API
        response = self._call_openai_api(system_prompt, user_prompt)
        
        # Parse the response to extract documentation updates
        docs_updates = self._parse_llm_response(response)
        
        return docs_updates
    
    def _create_system_prompt(self) -> str:
        """Create the system prompt for the LLM"""
        return """You are an expert technical documentation writer for the Vivified platform, a HIPAA-compliant 
enterprise application kernel. Your task is to create comprehensive, user-friendly documentation that takes 
full advantage of Material for MkDocs features.

Key Requirements:
1. NEVER include internal implementation details, phase numbers, version numbers like "v4", or development plans
2. Focus on user-facing features, APIs, and integration guides
3. Write for a dyslexic-friendly experience: use visual elements, clear sections, and minimal dense text
4. Utilize Material for MkDocs features extensively:
   - Admonitions (!!! note, !!! warning, !!! tip, !!! info, !!! success, !!! danger)
   - Code tabs for multi-language examples
   - Collapsible sections with ??? details
   - Mermaid diagrams for architecture and flows
   - Annotations for code blocks
   - Content tabs for different approaches/platforms
   - Icons and emojis for visual clarity
   
5. Structure documentation hierarchically with clear navigation
6. Include practical examples and use cases
7. Provide troubleshooting sections with common issues and solutions
8. Add API references with clear request/response examples
9. Create getting-started guides that are immediately actionable

Output Format:
Return a JSON object where keys are file paths (relative to docs/) and values are the complete markdown content.
Use proper Material for MkDocs syntax throughout.

Example features to use:
- Tabs: === "Python" ... === "Node.js" ...
- Admonitions: !!! tip "Pro Tip"
- Details: ??? note "Click to expand"
- Code annotations: # (1) for numbered explanations
- Mermaid: ```mermaid graph TD ...```
- Icons: :material-account: :material-security:
"""
    
    def _create_user_prompt(self, context: DocumentationContext) -> str:
        """Create the user prompt with full context"""
        
        # Check if this is a full scan or just recent changes
        is_full_scan = len(context.recent_changes) > 100
        
        # Build a comprehensive prompt
        prompt_parts = [
            "Generate comprehensive documentation for the Vivified platform based on the following context:",
            "",
            "## Platform Overview (from AGENTS.md)",
            context.agents_md[:5000],
            "",
        ]
        
        if is_full_scan:
            prompt_parts.extend([
                "## Full Repository Documentation Request",
                "This is a COMPLETE DOCUMENTATION GENERATION from the entire codebase.",
                f"The repository contains {len(context.recent_changes)} important files.",
                "Create comprehensive documentation covering ALL aspects of the platform.",
                "",
            ])
        else:
            prompt_parts.extend([
                "## Recent Changes",
                "The following files have been modified recently:",
                *[f"- {change}" for change in context.recent_changes[:30]],
            ])
        
        prompt_parts.extend([
            "",
            "## Core Services Available",
            *[f"### {name}\n{desc[:500]}" for name, desc in list(context.core_services.items())[:10]],
            "",
            "## API Specification (excerpt)",
            context.openapi_spec[:3000],
            "",
            "## Security Policies",
            context.security_policies[:2000],
            "",
            "## Canonical Models",
            context.canonical_models[:2000],
            "",
            "## Existing Documentation Structure",
            *[f"- {path}: {content[:100]}..." for path, content in list(context.existing_docs.items())[:20]],
            "",
            "## Admin UI Components",
            f"Available UI components: {', '.join(context.admin_ui_components[:20])}",
            "",
            "## Provider Configuration",
            context.provider_traits[:1500],
            "",
            "## Environment Configuration",
            context.env_example[:1000],
            "",
            "Please generate or update the following documentation sections:",
            "1. Getting Started Guide (getting-started.md)",
            "2. Core Services Documentation (core/*.md)",
            "3. Plugin Development Guide (plugins/development.md)",
            "4. API Reference (api-reference.md)",
            "5. Security & Compliance Guide (security.md)",
            "6. Admin Console Guide (admin-console.md)",
            "7. Troubleshooting Guide (troubleshooting.md)",
            "8. Configuration Reference (configuration.md)",
            "",
            "Remember to:",
            "- Use Material for MkDocs features extensively",
            "- Focus on practical, user-facing documentation",
            "- Include code examples with proper syntax highlighting",
            "- Add visual diagrams where helpful",
            "- Create a dyslexic-friendly reading experience",
            "- Exclude any internal development plans or phase numbers",
            "",
            "Return as JSON with file paths as keys and complete markdown content as values."
        ]
        
        return '\n'.join(prompt_parts)
    
    def _call_openai_api(self, system_prompt: str, user_prompt: str) -> str:
        """Call OpenAI API with the prompts"""
        
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.openai_api_key}",
            "Content-Type": "application/json",
        }
        
        # Use GPT-5 Mini for cost-effective, high-quality documentation
        # Available GPT-5 models (September 2025):
        # - gpt-5-chat-latest: Latest GPT-5 for chat (highest quality)
        # - gpt-5-mini-2025-08-07: Cost-effective, fast (recommended)
        # - gpt-5-nano-2025-08-07: Most economical for simpler tasks
        # 
        # Fallback options:
        # - gpt-4o: Previous generation, still excellent
        # - gpt-4o-mini: Budget-friendly GPT-4 variant
        
        model = os.getenv("OPENAI_MODEL", "gpt-5-mini-2025-08-07")  # Allow override via environment
        
        # Build request data - GPT-5 models have different parameter support
        data = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        
        # GPT-5 models have strict parameter requirements:
        # - Only support default temperature (1)
        # - Don't support max_tokens, response_format, etc.
        if model.startswith("gpt-5"):
            # GPT-5 models - minimal parameters only
            pass  # Using defaults
        else:
            # GPT-4 and other models - full parameter set
            data["temperature"] = 0.7  # Balance between creativity and consistency
            data["top_p"] = 0.95  # Nucleus sampling for quality
            data["frequency_penalty"] = 0.3  # Reduce repetition
            data["presence_penalty"] = 0.3  # Encourage covering all topics
            data["max_tokens"] = 16000  # Maximum response length
            data["response_format"] = {"type": "json_object"}  # Ensure structured output
        
        print(f"Using OpenAI model: {model}")
        
        try:
            response = requests.post(url, headers=headers, json=data, timeout=180)
            response.raise_for_status()
            result = response.json()
            return result["choices"][0]["message"]["content"]
        except Exception as e:
            print(f"Error calling OpenAI API with {model}: {e}")
            # Try with fallback model
            fallback_model = "gpt-4o"  # Reliable fallback with full parameter support
            print(f"Attempting fallback with {fallback_model}...")
            
            # Rebuild data for fallback with appropriate parameters
            data = {
                "model": fallback_model,
                "messages": data["messages"],
                "temperature": 0.7,
                "top_p": 0.95,
                "frequency_penalty": 0.3,
                "presence_penalty": 0.3,
                "max_tokens": 16000,
            }
            try:
                response = requests.post(url, headers=headers, json=data, timeout=180)
                response.raise_for_status()
                result = response.json()
                return result["choices"][0]["message"]["content"]
            except Exception as e2:
                print(f"Fallback also failed: {e2}")
                raise
    
    def _parse_llm_response(self, response: str) -> Dict[str, str]:
        """Parse the LLM response to extract documentation updates"""
        try:
            # Try to parse as JSON first
            docs = json.loads(response)
            if isinstance(docs, dict):
                return docs
        except json.JSONDecodeError:
            pass
        
        # Fallback: extract markdown sections
        docs = {}
        current_file = None
        current_content = []
        
        for line in response.split('\n'):
            if line.startswith('FILE:') or line.startswith('### FILE:'):
                if current_file and current_content:
                    docs[current_file] = '\n'.join(current_content)
                current_file = line.replace('FILE:', '').replace('### FILE:', '').strip()
                current_content = []
            else:
                current_content.append(line)
        
        if current_file and current_content:
            docs[current_file] = '\n'.join(current_content)
        
        return docs
    
    def update_mkdocs_config(self, docs_updates: Dict[str, str]) -> dict:
        """Update mkdocs.yml configuration with enhanced features"""
        
        mkdocs_path = self.repo_root / "mkdocs.yml"
        
        # Enhanced configuration
        config = {
            "site_name": "Vivified Platform Documentation",
            "site_description": "Enterprise-grade modular platform with HIPAA compliance",
            "site_url": "https://docs.vivified.dev",
            "repo_url": "https://github.com/DMontgomery40/vivified",
            "repo_name": "DMontgomery40/vivified",
            "copyright": "Copyright &copy; 2025 Vivified Platform",
            
            "theme": {
                "name": "material",
                "custom_dir": "docs/overrides",
                "language": "en",
                "palette": [
                    {
                        "scheme": "default",
                        "primary": "indigo",
                        "accent": "indigo",
                        "toggle": {
                            "icon": "material/brightness-7",
                            "name": "Switch to dark mode",
                        }
                    },
                    {
                        "scheme": "slate",
                        "primary": "indigo",
                        "accent": "indigo",
                        "toggle": {
                            "icon": "material/brightness-4",
                            "name": "Switch to light mode",
                        }
                    }
                ],
                "font": {
                    "text": "Roboto",
                    "code": "Roboto Mono",
                },
                "features": self.material_features,
                "icon": {
                    "logo": "material/shield-check",
                    "repo": "fontawesome/brands/github",
                    "admonition": {
                        "note": "material/note-text",
                        "info": "material/information",
                        "tip": "material/lightbulb",
                        "success": "material/check-circle",
                        "warning": "material/alert",
                        "danger": "material/alert-circle",
                    }
                }
            },
            
            "plugins": [
                "search",
                "mike",
                {"git-revision-date-localized": {
                    "enable_creation_date": True,
                    "type": "iso_datetime",
                }},
                "awesome-pages",
                {"minify": {
                    "minify_html": True,
                    "minify_js": True,
                    "minify_css": True,
                }},
                "macros",
            ],
            
            "markdown_extensions": [
                "admonition",
                "pymdownx.details",
                "pymdownx.superfences",
                "pymdownx.tabbed",
                "pymdownx.keys",
                "pymdownx.snippets",
                "pymdownx.progressbar",
                "attr_list",
                "md_in_html",
                "def_list",
                "footnotes",
                "tables",
                "pymdownx.arithmatex",
                "pymdownx.betterem",
                "pymdownx.caret",
                "pymdownx.mark",
                "pymdownx.tilde",
                "pymdownx.smartsymbols",
                "pymdownx.emoji",
                {"pymdownx.superfences": {
                    "custom_fences": [
                        {
                            "name": "mermaid",
                            "class": "mermaid",
                            "format": "!!python/name:pymdownx.superfences.fence_code_format",
                        }
                    ]
                }},
                {"pymdownx.tabbed": {
                    "alternate_style": True,
                }},
                {"pymdownx.tasklist": {
                    "custom_checkbox": True,
                }},
                {"pymdownx.highlight": {
                    "anchor_linenums": True,
                    "line_spans": "__span",
                    "pygments_lang_class": True,
                }},
                "pymdownx.inlinehilite",
                {"pymdownx.emoji": {
                    "emoji_index": "!!python/name:material.extensions.emoji.twemoji",
                    "emoji_generator": "!!python/name:material.extensions.emoji.to_svg",
                }},
            ],
            
            "extra": {
                "version": {
                    "provider": "mike",
                    "default": "latest",
                },
                "social": [
                    {
                        "icon": "fontawesome/brands/github",
                        "link": "https://github.com/DMontgomery40/vivified",
                    },
                ],
                "analytics": {
                    "provider": "google",
                    "property": "G-XXXXXXXXXX",  # Add your Google Analytics ID
                },
                "consent": {
                    "title": "Cookie consent",
                    "description": "We use cookies to recognize your repeated visits and preferences.",
                },
            },
            
            "extra_javascript": [
                "https://unpkg.com/mermaid@9/dist/mermaid.min.js",
            ],
            
            "nav": self._generate_navigation(docs_updates),
        }
        
        return config
    
    def _generate_navigation(self, docs_updates: Dict[str, str]) -> list:
        """Generate navigation structure based on documentation"""
        
        nav = [
            {"Home": "index.md"},
            {"Getting Started": [
                {"Quick Start": "getting-started.md"},
                {"Installation": "installation.md"},
                {"Configuration": "configuration.md"},
            ]},
            {"Core Platform": [
                {"Overview": "core/overview.md"},
                {"Architecture": "core/architecture.md"},
                {"Gateway": "core/gateway.md"},
                {"Identity & Auth": "core/identity.md"},
                {"Policy Engine": "core/policy.md"},
                {"Storage": "core/storage.md"},
                {"Messaging": "core/messaging.md"},
                {"Audit": "core/audit.md"},
            ]},
            {"Admin Console": [
                {"Overview": "admin-console.md"},
                {"Dashboard": "admin-console/dashboard.md"},
                {"User Management": "admin-console/users.md"},
                {"Configuration": "admin-console/configuration.md"},
                {"Monitoring": "admin-console/monitoring.md"},
            ]},
            {"Plugins": [
                {"Overview": "plugins/overview.md"},
                {"Development Guide": "plugins/development.md"},
                {"SDK Reference": "plugins/sdk.md"},
                {"Examples": "plugins/examples.md"},
            ]},
            {"API Reference": [
                {"REST API": "api-reference.md"},
                {"WebSocket API": "api/websocket.md"},
                {"GraphQL": "api/graphql.md"},
            ]},
            {"Security & Compliance": [
                {"Overview": "security.md"},
                {"HIPAA Compliance": "security/hipaa.md"},
                {"Authentication": "security/authentication.md"},
                {"Authorization": "security/authorization.md"},
                {"Encryption": "security/encryption.md"},
            ]},
            {"Operations": [
                {"Deployment": "deployment.md"},
                {"Monitoring": "monitoring.md"},
                {"Backup & Recovery": "backup.md"},
                {"Troubleshooting": "troubleshooting.md"},
            ]},
            {"Reference": [
                {"Environment Variables": "reference/env-vars.md"},
                {"CLI Commands": "reference/cli.md"},
                {"Error Codes": "reference/errors.md"},
                {"Glossary": "reference/glossary.md"},
            ]},
            {"Contributing": "contributing.md"},
        ]
        
        return nav
    
    def write_documentation_files(self, docs_updates: Dict[str, str]) -> None:
        """Write documentation files to disk"""
        
        docs_path = self.repo_root / "docs"
        docs_path.mkdir(exist_ok=True)
        
        for file_path, content in docs_updates.items():
            full_path = docs_path / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Filter content one more time before writing
            filtered_content = self._filter_sensitive_content(content)
            
            full_path.write_text(filtered_content, encoding="utf-8")
            print(f"Wrote: {file_path}")
    
    def write_mkdocs_config(self, config: dict) -> None:
        """Write mkdocs.yml configuration"""
        
        import yaml
        
        mkdocs_path = self.repo_root / "mkdocs.yml"
        
        with open(mkdocs_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        print(f"Updated: mkdocs.yml")
    
    def create_github_workflow(self) -> None:
        """Create enhanced GitHub workflow for documentation automation"""
        
        workflow = """name: Documentation Automation
on:
  push:
    branches: ["development", "main"]
  pull_request:
    branches: ["development"]
  workflow_dispatch:
    inputs:
      regenerate_all:
        description: 'Regenerate all documentation'
        required: false
        type: boolean
        default: false

permissions:
  contents: write
  pages: write
  id-token: write
  pull-requests: write

jobs:
  generate-docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          
      - name: Install dependencies
        run: |
          pip install -r docs/requirements.txt
          pip install requests pyyaml
          
      - name: Generate documentation with AI
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          python tools/scripts/docs_autopilot_enhanced.py
          
      - name: Create PR with documentation updates
        if: github.event_name != 'pull_request'
        uses: peter-evans/create-pull-request@v6
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          title: "docs: AI-generated documentation updates"
          body: |
            This PR contains AI-generated documentation updates based on recent code changes.
            
            **Please review carefully before merging.**
            
            - [ ] Documentation is accurate
            - [ ] No internal/sensitive information exposed
            - [ ] Material for MkDocs features utilized
            - [ ] Navigation structure is logical
          commit-message: "docs: update documentation with AI assistance"
          branch: docs/ai-updates-${{ github.run_id }}
          base: mkdocs
          
  deploy-docs:
    needs: generate-docs
    if: github.ref == 'refs/heads/mkdocs' || github.event_name == 'workflow_dispatch'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          ref: mkdocs
          
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          
      - name: Install dependencies
        run: pip install -r docs/requirements.txt
          
      - name: Configure git
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          
      - name: Build and deploy with mike
        run: |
          mike deploy --push --update-aliases latest dev
          mike set-default --push latest
          
      - name: Ensure CNAME file
        run: |
          git checkout gh-pages
          echo "docs.vivified.dev" > CNAME
          git add CNAME
          git commit -m "Add CNAME for custom domain" || true
          git push origin gh-pages
"""
        
        workflow_path = self.repo_root / ".github" / "workflows" / "docs-automation.yml"
        workflow_path.parent.mkdir(parents=True, exist_ok=True)
        workflow_path.write_text(workflow, encoding="utf-8")
        print(f"Created: {workflow_path}")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced Docs Autopilot")
    parser.add_argument("--base", default="origin/development", help="Base branch for comparison")
    parser.add_argument("--dry-run", action="store_true", help="Don't write files, just show what would be done")
    parser.add_argument("--regenerate-all", action="store_true", help="Regenerate all documentation from entire codebase")
    parser.add_argument("--full-scan", action="store_true", help="Scan entire repository, not just changes")
    args = parser.parse_args()
    
    autopilot = EnhancedDocsAutopilot()
    
    # Force full repository scan if regenerate-all or full-scan
    if args.regenerate_all or args.full_scan:
        print("🔄 Full repository scan mode - generating docs from entire codebase...")
        args.base = None  # This will make it scan everything
    
    print("Gathering comprehensive context...")
    context = autopilot.gather_comprehensive_context(args.base)
    
    print("Generating documentation with AI...")
    docs_updates = autopilot.generate_documentation_with_llm(context)
    
    if args.dry_run:
        print("\n=== DRY RUN - Would create/update the following files ===")
        for file_path in docs_updates.keys():
            print(f"  - docs/{file_path}")
        print("\n=== mkdocs.yml would be updated with enhanced configuration ===")
    else:
        print("Writing documentation files...")
        autopilot.write_documentation_files(docs_updates)
        
        print("Updating mkdocs.yml configuration...")
        config = autopilot.update_mkdocs_config(docs_updates)
        autopilot.write_mkdocs_config(config)
        
        print("Creating GitHub workflow...")
        autopilot.create_github_workflow()
        
        print("\n✅ Documentation automation setup complete!")
        print("Next steps:")
        print("1. Review the generated documentation")
        print("2. Commit and push changes to trigger the workflow")
        print("3. Monitor the GitHub Actions for documentation deployment")


if __name__ == "__main__":
    main()
