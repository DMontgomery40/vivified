#!/usr/bin/env python3
"""
Test script to generate ONE documentation file with rich Material features
"""

import os
import requests
import json

def generate_material_rich_doc():
    """Generate a single doc file to test Material features"""
    
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("❌ No API key")
        return
    
    system_prompt = """You are a documentation writer. You MUST use Material for MkDocs features.

REQUIREMENTS:
1. Use at least 5 different admonition types (!!! note, !!! tip, !!! warning, !!! danger, !!! example)
2. Use collapsible sections with ???
3. Use code tabs with === for Python, Node.js, and curl
4. Include a data table
5. Add a Mermaid diagram
6. Use grid cards
7. Add Material icons

Generate documentation for a "Getting Started" page that shows ALL these features."""

    user_prompt = """Create a Getting Started guide for the Vivified platform. 
    
Platform info:
- HIPAA-compliant healthcare platform
- Plugin-based architecture
- Docker-based deployment
- Python and Node.js SDKs
- REST API with authentication

MUST include:
- Grid cards at the top for quick links
- Multiple admonitions throughout
- Tabbed code examples
- Configuration table
- Architecture diagram
- Collapsible advanced sections

Make it visually rich with Material for MkDocs features!"""

    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    
    data = {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.7,
        "max_tokens": 4000,
    }
    
    print("🤖 Generating Material-rich documentation...")
    response = requests.post(url, headers=headers, json=data, timeout=60)
    
    if response.status_code == 200:
        content = response.json()["choices"][0]["message"]["content"]
        
        # Save to file
        with open("docs/getting-started-material.md", "w") as f:
            f.write(content)
        
        print("✅ Generated docs/getting-started-material.md")
        print("\n📄 Preview (first 500 chars):")
        print(content[:500])
        
        # Check for Material features
        features_found = []
        if "!!!" in content:
            features_found.append("✅ Admonitions")
        if "???" in content:
            features_found.append("✅ Collapsible sections")
        if "===" in content:
            features_found.append("✅ Code tabs")
        if "|--" in content or "| " in content:
            features_found.append("✅ Tables")
        if "mermaid" in content:
            features_found.append("✅ Diagrams")
        if ":material-" in content:
            features_found.append("✅ Icons")
        if "grid" in content:
            features_found.append("✅ Grid cards")
        
        print("\n🔍 Material Features Found:")
        for feature in features_found:
            print(f"   {feature}")
        
        if len(features_found) < 4:
            print("\n⚠️ WARNING: Not enough Material features used!")
            print("The AI might need more explicit instructions.")
    else:
        print(f"❌ API Error: {response.status_code}")
        print(response.text)

if __name__ == "__main__":
    generate_material_rich_doc()
