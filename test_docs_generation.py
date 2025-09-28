#!/usr/bin/env python3
"""
Test script for documentation generation with GPT-5
Run this to verify the OpenAI GPT-5 integration is working
"""

import os
import sys
from pathlib import Path

# Add the tools/scripts directory to the path
sys.path.insert(0, str(Path(__file__).parent / "tools" / "scripts"))

from docs_autopilot_enhanced import EnhancedDocsAutopilot

def main():
    """Test the documentation generation"""
    
    # Check for API key
    if not os.getenv("OPENAI_API_KEY"):
        print("❌ Error: OPENAI_API_KEY environment variable not set")
        print("Please set it: export OPENAI_API_KEY=your-api-key")
        return 1
    
    print("✅ OpenAI API key found")
    
    # Initialize the autopilot
    autopilot = EnhancedDocsAutopilot(repo_root=Path.cwd())
    
    model = os.getenv('OPENAI_MODEL', 'gpt-5-mini-2025-08-07')
    print(f"📚 Using model: {model}")
    print(f"📅 Date: September 2025")
    
    # Test gathering context
    print("\n🔍 Gathering context from repository...")
    try:
        context = autopilot.gather_comprehensive_context()
        print(f"  ✓ Found {len(context.recent_changes)} recent changes")
        print(f"  ✓ Found {len(context.core_services)} core services")
        print(f"  ✓ Found {len(context.existing_docs)} existing docs")
    except Exception as e:
        print(f"❌ Error gathering context: {e}")
        return 1
    
    # Test a simple API call with a minimal prompt
    print("\n🤖 Testing OpenAI GPT-5 API connection...")
    try:
        # GPT-5 models work best with direct prompts, not JSON mode
        test_prompt = "Reply with a simple JSON object containing test:success, no other text"
        response = autopilot._call_openai_api(
            "You are a helpful assistant. Generate only valid JSON.",
            test_prompt
        )
        print(f"  ✓ GPT-5 API call successful")
        print(f"  Response preview: {response[:100]}...")
    except Exception as e:
        print(f"❌ Error calling OpenAI API: {e}")
        print("\nTroubleshooting tips:")
        print("1. Verify your API key is correct")
        print("2. Check your OpenAI account has credits")
        print("3. Available GPT-5 models (Sept 2025):")
        print("   - gpt-5-chat-latest (highest quality)")
        print("   - gpt-5-mini-2025-08-07 (recommended)")
        print("   - gpt-5-nano-2025-08-07 (most economical)")
        print("4. Try: export OPENAI_MODEL=gpt-5-nano-2025-08-07")
        return 1
    
    print("\n✅ All tests passed! GPT-5 documentation automation is ready.")
    print("\nTo generate full documentation, run:")
    print("  python tools/scripts/docs_autopilot_enhanced.py")
    print("\nOr trigger via GitHub Actions:")
    print("  1. Push to development or main branch")
    print("  2. Or manually trigger the 'Documentation Automation' workflow")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
