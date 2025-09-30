#!/usr/bin/env python3
"""
Check which OpenAI models are actually available via the API
"""

import os
import requests
import json

def list_available_models():
    """List all available OpenAI models"""
    
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("❌ OPENAI_API_KEY not set")
        return
    
    url = "https://api.openai.com/v1/models"
    headers = {
        "Authorization": f"Bearer {api_key}",
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        models = response.json()
        
        # Filter for chat models
        chat_models = []
        for model in models['data']:
            model_id = model['id']
            # Look for GPT models, o1 models, etc.
            if any(prefix in model_id for prefix in ['gpt-', 'o1-', 'davinci', 'text-']):
                chat_models.append(model_id)
        
        # Sort models
        chat_models.sort()
        
        print("🤖 Available OpenAI Models:")
        print("=" * 50)
        
        # Group by model family
        gpt5_models = [m for m in chat_models if 'gpt-5' in m]
        gpt4o_models = [m for m in chat_models if 'gpt-4o' in m]
        gpt4_models = [m for m in chat_models if 'gpt-4' in m and 'gpt-4o' not in m]
        o1_models = [m for m in chat_models if 'o1-' in m]
        gpt35_models = [m for m in chat_models if 'gpt-3.5' in m]
        other_models = [m for m in chat_models if m not in gpt5_models + gpt4o_models + gpt4_models + o1_models + gpt35_models]
        
        if gpt5_models:
            print("\n📌 GPT-5 Models:")
            for model in gpt5_models:
                print(f"  • {model}")
        
        if o1_models:
            print("\n🧠 O1 Reasoning Models:")
            for model in o1_models:
                print(f"  • {model}")
        
        if gpt4o_models:
            print("\n⚡ GPT-4O Models (Latest):")
            for model in gpt4o_models:
                print(f"  • {model}")
        
        if gpt4_models:
            print("\n🎯 GPT-4 Models:")
            for model in gpt4_models:
                print(f"  • {model}")
        
        if gpt35_models:
            print("\n💰 GPT-3.5 Models (Budget):")
            for model in gpt35_models:
                print(f"  • {model}")
        
        if other_models:
            print("\n🔧 Other Models:")
            for model in other_models:
                print(f"  • {model}")
        
        # Test specific models
        print("\n" + "=" * 50)
        print("🧪 Testing specific models for chat completions:")
        
        test_models = [
            "gpt-5",
            "gpt-5-mini", 
            "gpt-5-nano",
            "o1-preview",
            "o1-mini",
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-4-turbo",
        ]
        
        for model in test_models:
            result = test_model(api_key, model)
            print(f"  {model}: {result}")
        
    except Exception as e:
        print(f"❌ Error: {e}")

def test_model(api_key, model_name):
    """Test if a specific model works with chat completions"""
    
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    
    data = {
        "model": model_name,
        "messages": [
            {"role": "user", "content": "Say 'test'"}
        ],
        "max_tokens": 10,
    }
    
    try:
        response = requests.post(url, headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            return "✅ Available"
        elif response.status_code == 404:
            return "❌ Not found"
        elif response.status_code == 400:
            error_data = response.json()
            if "model" in str(error_data):
                return "❌ Model not available"
            else:
                return f"⚠️ Bad request: {error_data.get('error', {}).get('message', 'Unknown')[:50]}"
        else:
            return f"⚠️ Status {response.status_code}"
    except Exception as e:
        return f"❌ Error: {str(e)[:30]}"

if __name__ == "__main__":
    list_available_models()
