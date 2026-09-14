import click
from ..log import get_logger

__name__ = "sinduk.commands.ai"

logger = get_logger(__name__)


@click.command()
def ai():
    """AI command."""
    click.echo("AI command is not implemented yet.")
    logger.info("AI command is not implemented yet.")
