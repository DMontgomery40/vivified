#!/usr/bin/env python3
"""
Vivified CLI (developer tooling)

Commands:
  scaffold   - Generate plugin scaffold archive via Admin API
  register   - Register a plugin manifest JSON with core
  publish    - Publish a canonical event
  schema     - Manage canonical JSON Schemas (list/upsert/activate/validate)

Env:
  VIVI_URL   - Base URL (default http://localhost:8000)
  VIVI_KEY   - API key (e.g., bootstrap_admin_only for dev)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import pathlib
import requests


def _base() -> str:
    return os.getenv("VIVI_URL", "http://localhost:8000").rstrip("/")


def _headers() -> dict:
    key = os.getenv("VIVI_KEY", "bootstrap_admin_only")
    return {"Authorization": f"Bearer {key}", "X-API-Key": key, "Content-Type": "application/json"}


def cmd_scaffold(args):
    url = f"{_base()}/admin/plugins/scaffold"
    payload = {
        "id": args.id,
        "name": args.name or args.id,
        "version": args.version or "1.0.0",
        "language": args.language,
        "traits": args.traits or ["communication_plugin"],
    }
    r = requests.post(url, headers=_headers(), data=json.dumps(payload))
    r.raise_for_status()
    out = pathlib.Path(args.output or f"{args.id}_scaffold.zip")
    out.write_bytes(r.content)
    print(f"wrote {out}")


def cmd_register(args):
    url = f"{_base()}/plugins/register"
    manifest = json.loads(pathlib.Path(args.manifest).read_text())
    r = requests.post(url, headers=_headers(), data=json.dumps(manifest))
    r.raise_for_status()
    print(json.dumps(r.json(), indent=2))


def cmd_publish(args):
    url = f"{_base()}/messaging/events"
    payload = {
        "event_type": args.event_type,
        "payload": json.loads(args.payload or "{}"),
        "source_plugin": args.source_plugin,
        "data_traits": args.data_traits or [],
    }
    r = requests.post(url, headers=_headers(), data=json.dumps(payload))
    r.raise_for_status()
    print(json.dumps(r.json(), indent=2))


def main(argv=None):
    p = argparse.ArgumentParser(prog="vivi")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scaffold")
    s.add_argument("id")
    s.add_argument("--name")
    s.add_argument("--version")
    s.add_argument("--language", default="python", choices=["python", "node"])
    s.add_argument("--traits", nargs="*")
    s.add_argument("--output")
    s.set_defaults(func=cmd_scaffold)

    r = sub.add_parser("register")
    r.add_argument("manifest")
    r.set_defaults(func=cmd_register)

    e = sub.add_parser("publish")
    e.add_argument("event_type")
    e.add_argument("source_plugin")
    e.add_argument("--payload")
    e.add_argument("--data_traits", nargs="*")
    e.set_defaults(func=cmd_publish)

    # schema subcommands
    sch = sub.add_parser("schema")
    ssub = sch.add_subparsers(dest="schema_cmd", required=True)

    def _reqs(url: str, payload: dict | None = None):
        r = requests.get(url, headers=_headers()) if payload is None else requests.post(url, headers=_headers(), data=json.dumps(payload))
        r.raise_for_status()
        return r

    def _schema_list(args):
        r = _reqs(f"{_base()}/schemas/{args.name}")
        print(json.dumps(r.json(), indent=2))
        return 0

    l = ssub.add_parser("list")
    l.add_argument("name")
    l.set_defaults(func=_schema_list)

    def _schema_upsert(args):
        data = json.loads(pathlib.Path(args.file).read_text())
        maj, min_, pat = (args.version or "1.0.0").split(".")
        payload = {"name": args.name, "major": int(maj), "minor": int(min_ or 0), "patch": int(pat or 0), "schema_data": data}
        r = _reqs(f"{_base()}/schemas", payload)
        print(json.dumps(r.json(), indent=2))
        return 0

    u = ssub.add_parser("upsert")
    u.add_argument("name")
    u.add_argument("version")
    u.add_argument("file")
    u.set_defaults(func=_schema_upsert)

    def _schema_activate(args):
        maj, min_, pat = (args.version or "1.0.0").split(".")
        payload = {"name": args.name, "major": int(maj), "minor": int(min_ or 0), "patch": int(pat or 0)}
        r = _reqs(f"{_base()}/schemas/activate", payload)
        print(json.dumps(r.json(), indent=2))
        return 0

    a = ssub.add_parser("activate")
    a.add_argument("name")
    a.add_argument("version")
    a.set_defaults(func=_schema_activate)

    def _schema_validate(args):
        payload_data = json.loads(pathlib.Path(args.file).read_text())
        body = {"payload": payload_data}
        if args.version:
            body["version"] = args.version
        elif args.major is not None:
            body["major"] = int(args.major)
        else:
            print("Provide --version x.y.z or --major N", file=sys.stderr)
            return 2
        r = _reqs(f"{_base()}/schemas/{args.name}/validate", body)
        print(json.dumps(r.json(), indent=2))
        return 0

    vsch = ssub.add_parser("validate")
    vsch.add_argument("name")
    vsch.add_argument("--version")
    vsch.add_argument("--major", type=int)
    vsch.add_argument("--file", required=True)
    vsch.set_defaults(func=_schema_validate)

    v = sub.add_parser("validate-manifest")
    v.add_argument("manifest")
    def _validate(args):
        try:
            mf = json.loads(pathlib.Path(args.manifest).read_text())
        except Exception as ex:
            print(f"invalid json: {ex}")
            return 1
        required = ["id","name","version","contracts","traits","security","compliance"]
        missing = [k for k in required if k not in mf]
        if missing:
            print(f"missing fields: {', '.join(missing)}")
            return 2
        if not isinstance(mf.get("contracts"), list) or not isinstance(mf.get("traits"), list):
            print("contracts and traits must be lists")
            return 3
        print("manifest looks valid")
        return 0
    v.set_defaults(func=_validate)

    t = sub.add_parser("transform-dryrun")
    t.add_argument("source_plugin")
    t.add_argument("target_plugin")
    t.add_argument("--user", help="user data json", default='{}')
    def _dryrun(args):
        url = f"{_base()}/canonical/normalize/user"
        data = json.loads(args.user)
        r = requests.post(url, headers=_headers(), data=json.dumps({
            "user_data": data, "source_plugin": args.source_plugin, "target_plugin": args.target_plugin
        }))
        r.raise_for_status()
        print(json.dumps(r.json(), indent=2))
        return 0
    t.set_defaults(func=_dryrun)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
