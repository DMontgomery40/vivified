#!/usr/bin/env python3
"""
Incremental Documentation Generator for Vivified Platform
Generates docs one service at a time to avoid API timeouts
"""

import os
import json
import requests
from pathlib import Path
from typing import Dict, List

class IncrementalDocsGenerator:
    def __init__(self, repo_root: Path = None):
        self.repo_root = Path(repo_root or os.getcwd())
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        
    def generate_service_docs(self, service_name: str) -> str:
        """Generate documentation for a specific core service"""
        
        service_path = self.repo_root / "core" / service_name
        if not service_path.exists():
            return ""
            
        # Gather service context
        context = self._gather_service_context(service_path, service_name)
        
        # Generate docs with OpenAI
        prompt = self._create_service_prompt(service_name, context)
        
        try:
            response = self._call_openai_api(prompt)
            return response
        except Exception as e:
            print(f"Error generating docs for {service_name}: {e}")
            return ""
    
    def _gather_service_context(self, service_path: Path, service_name: str) -> Dict:
        """Gather context for a specific service"""
        context = {
            "name": service_name,
            "files": [],
            "main_files": [],
            "readme": "",
            "docstrings": [],
        }
        
        # Get Python files
        for py_file in service_path.rglob("*.py"):
            if py_file.name != "__pycache__":
                try:
                    content = py_file.read_text(encoding="utf-8")[:2000]  # Limit size
                    context["files"].append({
                        "path": str(py_file.relative_to(service_path)),
                        "content": content
                    })
                    
                    # Extract main classes/functions
                    if "class " in content or "def " in content:
                        context["main_files"].append({
                            "path": str(py_file.relative_to(service_path)),
                            "content": content
                        })
                except:
                    pass
        
        # Get README if exists
        readme_path = service_path / "README.md"
        if readme_path.exists():
            try:
                context["readme"] = readme_path.read_text(encoding="utf-8")
            except:
                pass
                
        return context
    
    def _create_service_prompt(self, service_name: str, context: Dict) -> str:
        """Create focused prompt for a single service"""
        
        files_summary = "\n".join([
            f"### {f['path']}\n```python\n{f['content'][:1000]}\n```"
            for f in context["main_files"][:5]  # Limit to 5 main files
        ])
        
        return f"""Generate comprehensive documentation for the {service_name} service in the Vivified platform.

This is a HIPAA-compliant enterprise platform service. Create detailed documentation using Material for MkDocs features.

## Service Context:
**Service Name:** {service_name}
**README:** {context["readme"][:1000]}

## Key Files:
{files_summary}

## Requirements:
1. Use Material for MkDocs admonitions (!!! note, !!! warning, !!! tip)
2. Include code examples with tabs (=== "Python", === "curl")
3. Add Mermaid diagrams for architecture/flow
4. Use data tables for configuration options
5. Include security considerations
6. Add troubleshooting section

## Output Format:
Return a JSON object with:
- "overview": Main service documentation (markdown)
- "api": API reference if applicable (markdown)  
- "config": Configuration guide (markdown)
- "examples": Usage examples (markdown)

Focus on practical usage, security implications, and HIPAA compliance aspects.
"""

    def _call_openai_api(self, prompt: str) -> str:
        """Call OpenAI API with shorter timeout for single service"""
        
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.openai_api_key}",
            "Content-Type": "application/json",
        }
        
        data = {
            "model": "gpt-4o",  # Use reliable model
            "messages": [
                {"role": "system", "content": "You are a technical documentation expert for enterprise HIPAA-compliant systems."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 4000,  # Reasonable limit
        }
        
        response = requests.post(url, headers=headers, json=data, timeout=60)  # Shorter timeout
        response.raise_for_status()
        result = response.json()
        return result["choices"][0]["message"]["content"]

def main():
    """Generate docs for all core services incrementally"""
    
    generator = IncrementalDocsGenerator()
    
    # Core services to document
    core_services = [
        "gateway", "identity", "policy", "storage", "messaging", 
        "audit", "config", "plugin_manager", "canonical", "api",
        "admin_ui", "security", "monitoring", "notifications"
    ]
    
    docs_path = Path("docs")
    docs_path.mkdir(exist_ok=True)
    
    for service in core_services:
        print(f"Generating docs for {service}...")
        
        try:
            docs_content = generator.generate_service_docs(service)
            
            if docs_content:
                # Try to parse as JSON
                try:
                    docs_json = json.loads(docs_content)
                    
                    # Write each section
                    service_dir = docs_path / "core" / service
                    service_dir.mkdir(parents=True, exist_ok=True)
                    
                    for section, content in docs_json.items():
                        if content and content.strip():
                            section_file = service_dir / f"{section}.md"
                            section_file.write_text(content, encoding="utf-8")
                            print(f"  ✅ Created {section_file}")
                            
                except json.JSONDecodeError:
                    # Fallback: write as single file
                    service_file = docs_path / "core" / f"{service}.md"
                    service_file.write_text(docs_content, encoding="utf-8")
                    print(f"  ✅ Created {service_file}")
            else:
                print(f"  ❌ No content generated for {service}")
                
        except Exception as e:
            print(f"  ❌ Error processing {service}: {e}")
            continue

if __name__ == "__main__":
    main()
