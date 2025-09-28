import json
from pathlib import Path
import click
from jsonschema import validate


@click.group()
def cli():
    """Vivified CLI"""


@cli.command("validate-manifest")
@click.option("--file", "file_", required=True, type=click.Path(exists=True))
def validate_manifest(file_: str):
    p = Path(file_)
    data = json.loads(Path(file_).read_text())
    schema = json.loads((Path(__file__).resolve().parents[2] / "validator" / "manifest_schema.json").read_text())
    validate(instance=data, schema=schema)
    click.echo("✓ Manifest is valid")


@cli.command("create-plugin")
@click.option("--lang", type=click.Choice(["python", "node"]), required=True)
@click.option("--name", required=True)
@click.option("--type", "ptype", default="communication")
def create_plugin(lang: str, name: str, ptype: str):
    plugins_dir = Path.cwd() / "plugins" / name
    plugins_dir.mkdir(parents=True, exist_ok=True)
    plugin_id = name.lower().replace(" ", "-").replace("_", "-")
    manifest = {
        "id": plugin_id,
        "name": name,
        "version": "0.1.0",
        "contracts": [],
        "traits": [],
        "dependencies": [],
        "allowed_domains": [],
        "endpoints": {"health": "/health"},
        "security": {"authentication_required": True, "data_classification": ["internal"]},
        "compliance": {"hipaa_controls": [], "audit_level": "basic"},
    }
    (plugins_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    click.echo(str(plugins_dir))


