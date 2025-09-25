import os, sys, re, pathlib

ROOT = pathlib.Path(".").resolve()
WORD_VIVIFIED = re.compile(r'\bvivified\b(?!\.dev)')
WORD_VIVIFIED_CAP = re.compile(r'\bVivified\b(?!\.dev)')

def is_binary(path: pathlib.Path) -> bool:
    try:
        with open(path, 'rb') as f:
            chunk = f.read(4096)
        if b'\x00' in chunk: return True
        # heuristic: lots of non-text
        text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20,0x100)))
        return bool(chunk) and (sum(c in text_chars for c in chunk) / len(chunk) < 0.9)
    except Exception:
        return True

changed = 0
scanned = 0
for p in ROOT.rglob('*'):
    if not p.is_file(): continue
    if p.suffix.lower() in {'.png','.jpg','.jpeg','.gif','.webp','.ico','.pdf','.zip','.gz','.bz2','.xz','.woff','.woff2','.ttf','.otf'}:
        continue
    if any(seg.startswith('.') and seg not in {'.env','.env.local'} for seg in p.parts):
        # skip .git, .venv, node_modules, etc.
        continue
    if 'node_modules' in p.parts or '.git' in p.parts or '.venv' in p.parts or 'dist' in p.parts or 'build' in p.parts:
        continue
    try:
        text = p.read_text(encoding='utf-8')
    except Exception:
        continue
    scanned += 1
    new_text = WORD_VIVIFIED_CAP.sub('Vivi', WORD_VIVIFIED.sub('vivi', text))
    if new_text != text:
        p.write_text(new_text, encoding='utf-8')
        print(f"[REPLACED] {p}")
        changed += 1

print(f"Scanned {scanned} files; changed {changed} files.")
