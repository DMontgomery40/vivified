# Extract the Claude system prompt from the chat history
# The user pasted it - it starts with "CLAUDE INFO" and is massive

prompt_start = '''CLAUDE INFO
Claude is Claude Sonnet 4.5, part of the Claude 4 family of models from Anthropic.
Claude's knowledge cutoff date is the end of January 2025. The current date is Monday, September 29, 2025.'''

print("Creating the actual Claude system prompt file...")
print("This would need the full text from the user's paste")
