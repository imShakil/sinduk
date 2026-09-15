import os
import sys
import click
from .commands.admin import init, passwd, change_master_key, version
from .commands.secrets import add, get, get_by_id, list, update, update_by_id, delete, delete_by_id
from .commands.ssh import ssh
from .commands.utils import export, cc
from .commands.backup import backup
from .commands.web import web
from .commands.team import team
from .commands.sync import sync
from .commands.server import server
from .commands.login import login_cmd as login, logout_cmd as logout


from . import __version__


class SindukGroup(click.Group):
    def main(self, *args, **kwargs):
        if len(sys.argv) > 0 and os.path.basename(sys.argv[0]) == "pacli":
            click.echo(
                "⚠️  Notice: 'pacli' is deprecated and has been renamed to 'sinduk'. Please use 'sinduk'.\n",
                err=True,
            )
        return super().main(*args, **kwargs)


@click.group(cls=SindukGroup)
@click.version_option(__version__, "-v", "--version", message="%(version)s")
def cli():
    """🔐 sinduk - Local-first zero-knowledge secrets & team vault manager."""
    pass


# Admin
cli.add_command(init)
cli.add_command(passwd)
cli.add_command(change_master_key)
cli.add_command(version)

# Secrets
cli.add_command(add)
cli.add_command(get)
cli.add_command(get_by_id)
cli.add_command(list)
cli.add_command(update)
cli.add_command(update_by_id)
cli.add_command(delete)
cli.add_command(delete_by_id)

# SSH
cli.add_command(ssh)

# Utils
cli.add_command(export)
cli.add_command(cc)

# Backup
cli.add_command(backup)

# Web UI
cli.add_command(web)

# Team
cli.add_command(team)

# Sync
cli.add_command(sync)

# Server (Option B - Self-hosted sync relay)
cli.add_command(server)

# Auth
cli.add_command(login)
cli.add_command(logout)
