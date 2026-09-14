import os
import sys
import json
import csv
import click
import datetime
from ..store import SecretStore
from ..log import get_logger
from ..decorators import master_password_required
from ..helpers import copy_to_clipboard
from ..linklyhq import LinklyHQ

logger = get_logger("sinduk.commands.utils")


@click.command()
@click.option("--format", "-f", type=click.Choice(["json", "csv"]), default="csv", help="Export format (json or csv)")
@click.option("--output", "-o", help="Output file path")
@master_password_required
def export(format, output):
    """Export secrets to JSON or CSV format."""
    store = SecretStore()
    secrets = store.list_secrets()
    if not secrets:
        click.echo("❌ No secrets to export.")
        return

    export_data = []
    for sid, label, stype, ctime, utime in secrets:
        secret_data = store.get_secret_by_id(sid)
        if secret_data:
            export_data.append(
                {
                    "id": sid,
                    "label": label,
                    "secret": secret_data["secret"],
                    "type": stype,
                    "created": datetime.datetime.fromtimestamp(ctime).isoformat() if ctime else None,
                    "updated": datetime.datetime.fromtimestamp(utime).isoformat() if utime else None,
                }
            )

    if not output:
        output = f"sinduk_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"

    try:
        if format == "json":
            with open(output, "w") as f:
                json.dump(export_data, f, indent=2)
        else:  # csv
            with open(output, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["id", "label", "secret", "type", "created", "updated"])
                writer.writeheader()
                writer.writerows(export_data)

        click.echo(f"✅ Exported {len(export_data)} secrets to {output}")
        logger.info(f"Exported {len(export_data)} secrets to {output}")
    except Exception as e:
        click.echo(f"❌ Export failed: {e}")
        logger.error(f"Export failed: {e}")


@click.command()
@click.argument("url", required=True)
@click.option("--name", "-n", help="Custom name for the shortened URL")
@click.option("--clip", "-c", is_flag=True, help="Copy the shortened URL to clipboard instead of printing.")
def short(url, name, clip):
    """Shorten URL with linklyhq.com. To use this feature you must have linklyhq.com API and Workspace ID"""
    api_key = os.getenv("PACLI_LINKLYHQ_KEY")
    workspace_id = os.getenv("PACLI_LINKLYHQ_WID")

    if not api_key or not workspace_id:
        click.echo("❌ API KEY not found. Set PACLI_LINKLYHQ_KEY and PACLI_LINKLYHQ_WID environment variables.")
        return
    linklyhq = LinklyHQ(api_key, workspace_id)
    shortened_url = linklyhq.shorten(url, name)
    if shortened_url:
        if clip:
            copy_to_clipboard(shortened_url)
        else:
            click.echo(f"🔗 Shortened URL: {shortened_url}")
    else:
        click.echo("❌ Failed to shorten URL.")
        logger.error(f"Failed to shorten URL: {url}")


@click.command()
def cc():
    """Copy stdin content to clipboard."""
    try:
        content = sys.stdin.read()
        if not content:
            click.echo("❌ No input received from stdin.")
            return
        copy_to_clipboard(content)
        logger.info("Content copied to clipboard from stdin")
    except Exception as e:
        click.echo(f"❌ Failed to read from stdin: {e}")
        logger.error(f"Failed to read from stdin: {e}")
