import click
import datetime
import pyperclip
from .log import get_logger

logger = get_logger("sinduk.helpers")


def choice_one(label, matches):
    """Helper function to select one secret from multiple matches."""
    click.echo(f"Multiple secrets found for label '{label}':")
    for idx, s in enumerate(matches, 1):
        cstr = (
            datetime.datetime.fromtimestamp(s["creation_time"]).strftime("%Y-%m-%d %H:%M:%S")
            if s["creation_time"]
            else ""
        )
        ustr = (
            datetime.datetime.fromtimestamp(s["update_time"]).strftime("%Y-%m-%d %H:%M:%S") if s["update_time"] else ""
        )
        click.echo(f"[{idx}] ID: {s['id']}  Type: {s['type']}  Created: {cstr}  Updated: {ustr}")
    while True:
        choice = click.prompt("Select which secret to retrieve (number)", type=int)
        if 1 <= choice <= len(matches):
            selected = matches[choice - 1]
            break
        click.echo("Invalid selection. Try again.")
    return selected


def copy_to_clipboard(secret):
    """Copy text to clipboard."""
    try:
        pyperclip.copy(secret)
        click.echo("📋 Secret copied to clipboard.")
    except ImportError:
        click.echo("❌ pyperclip is not installed. Run 'pip install pyperclip' to enable clipboard support.")
    except Exception as e:
        click.echo(f"❌ Failed to copy to clipboard: {e}")
