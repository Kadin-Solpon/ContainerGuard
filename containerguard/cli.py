import click
from containerguard.scanner import scan_image, scan_runtime

@click.group()
def cli():
    """ContainerGuard — Docker container security scanner."""
    pass

@cli.command()
@click.argument("image")
def scan(image):
    """Scan a Docker image for security misconfigurations."""
    click.echo("Hello from ContainerGuard")
    click.echo(f"Scanning image: {image}")
    scan_image(image)

@cli.command("scan-runtime")
@click.argument("container_id")
def scan_runtime_cmd(container_id):
    """Scan a running container for security misconfigurations."""
    click.echo("Hello from ContainerGuard")
    click.echo(f"Scanning running container: {container_id}")
    scan_runtime(container_id)

if __name__ == "__main__":
    cli()
