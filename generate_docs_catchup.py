#!/usr/bin/env python3
"""
Generate comprehensive documentation from the entire existing codebase.
This script is designed to "catch up" and document all code that was 
pushed before the documentation automation was working.
"""

import os
import sys
import subprocess
from pathlib import Path

def main():
    """Generate full documentation from entire repository"""
    
    print("🚀 Vivified Documentation Generator - Catch-Up Mode")
    print("=" * 60)
    print()
    
    # Check for OpenAI API key
    if not os.getenv("OPENAI_API_KEY"):
        print("❌ Error: OPENAI_API_KEY environment variable not set")
        print("Please set it: export OPENAI_API_KEY=your-api-key")
        return 1
    
    print("✅ OpenAI API key found")
    
    # Get current branch
    current_branch = subprocess.check_output(
        ["git", "branch", "--show-current"], 
        text=True
    ).strip()
    print(f"📍 Current branch: {current_branch}")
    print()
    
    # Inform user what we're doing
    print("📚 This will generate comprehensive documentation by:")
    print("   1. Scanning the ENTIRE repository (not just recent changes)")
    print("   2. Reading all core services, plugins, and configuration")
    print("   3. Creating complete documentation for everything")
    print()
    print("⏳ This may take a few minutes due to the comprehensive scan...")
    print()
    
    # Add the tools/scripts directory to Python path
    repo_root = Path.cwd()
    sys.path.insert(0, str(repo_root / "tools" / "scripts"))
    
    try:
        # Import and run the enhanced docs autopilot
        from docs_autopilot_enhanced import EnhancedDocsAutopilot
        
        print("🔍 Phase 1: Gathering context from entire repository...")
        autopilot = EnhancedDocsAutopilot(repo_root=repo_root)
        
        # Force full scan by passing None as base_ref
        context = autopilot.gather_comprehensive_context(base_ref=None)
        
        print(f"   ✓ Found {len(context.recent_changes)} files to document")
        print(f"   ✓ Found {len(context.core_services)} core services")
        print(f"   ✓ Found {len(context.plugin_manifests)} plugins")
        print(f"   ✓ Found {len(context.admin_ui_components)} UI components")
        print()
        
        print("🤖 Phase 2: Generating documentation with GPT-5...")
        print(f"   Using model: {os.getenv('OPENAI_MODEL', 'gpt-5-mini-2025-08-07')}")
        
        # Generate comprehensive documentation
        docs_updates = autopilot.generate_documentation_with_llm(context)
        
        if not docs_updates:
            print("❌ No documentation was generated. Check API errors above.")
            return 1
        
        print(f"   ✓ Generated {len(docs_updates)} documentation files")
        print()
        
        print("💾 Phase 3: Writing documentation files...")
        autopilot.write_documentation_files(docs_updates)
        
        print("📝 Phase 4: Updating mkdocs.yml configuration...")
        config = autopilot.update_mkdocs_config(docs_updates)
        autopilot.write_mkdocs_config(config)
        
        print()
        print("✅ Documentation generation complete!")
        print()
        print("📂 Generated files:")
        for doc_path in sorted(docs_updates.keys())[:10]:
            print(f"   - docs/{doc_path}")
        if len(docs_updates) > 10:
            print(f"   ... and {len(docs_updates) - 10} more files")
        
        print()
        print("📋 Next steps:")
        print("1. Review generated docs: ls -la docs/")
        print("2. Stage changes: git add docs/ mkdocs.yml")
        print("3. Commit: git commit -m 'docs: comprehensive documentation from full repository scan'")
        print("4. Push to trigger deployment: git push origin " + current_branch)
        print()
        print("After merge to mkdocs branch, docs will deploy to https://docs.vivified.dev")
        
        return 0
        
    except ImportError as e:
        print(f"❌ Error importing docs autopilot: {e}")
        print("Make sure you're in the vivified repository root")
        return 1
    except Exception as e:
        print(f"❌ Error generating documentation: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
