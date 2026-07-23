import click
from containerguard.scanner import scan_image, scan_runtime, scan_dockerfile

# Reusable --output option shared by every scan command.
output_option = click.option(
    "-o", "--output",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
    help="Output format for findings.",
)

# Reusable --pdf option: write a PDF report to the given path.
pdf_option = click.option(
    "--pdf",
    "pdf_path",
    type=click.Path(),
    default=None,
    help="Also write a PDF report to this path.",
)


@click.group()
def cli():
    """ContainerGuard — Docker container security scanner."""
    pass


def _do_scan(image, output, pdf_path=None):
    if output != "json":
        click.echo("Hello from ContainerGuard")
        click.echo(f"Scanning image: {image}")
    return scan_image(image, output=output, pdf_path=pdf_path)

def _do_scan_runtime(container_id, output, pdf_path=None):
    if output != "json":
        click.echo("Hello from ContainerGuard")
        click.echo(f"Scanning running container: {container_id}")
    return scan_runtime(container_id, output=output, pdf_path=pdf_path)

def _do_scan_dockerfile(dockerfile, output, pdf_path=None):
    if output != "json":
        click.echo("Hello from ContainerGuard")
        click.echo(f"Scanning Dockerfile: {dockerfile}")
    return scan_dockerfile(dockerfile, output=output, pdf_path=pdf_path)


@cli.command()
@click.argument("image")
@output_option
@pdf_option
def scan(image, output, pdf_path):
    """Scan a Docker image for security misconfigurations."""
    _do_scan(image, output, pdf_path)

@cli.command("scan-runtime")
@click.argument("container_id")
@output_option
@pdf_option
def scan_runtime_cmd(container_id, output, pdf_path):
    """Scan a running container for security misconfigurations."""
    _do_scan_runtime(container_id, output, pdf_path)

@cli.command("scan-dockerfile")
@click.argument("dockerfile", type=click.Path(exists=True))
@output_option
@pdf_option
def scan_dockerfile_cmd(dockerfile, output, pdf_path):
    """Scan a Dockerfile for base-image pinning misconfigurations."""
    _do_scan_dockerfile(dockerfile, output, pdf_path)

@cli.command("all-scans")
@click.argument("image")
@click.argument("container_id")
@click.argument("dockerfile", type=click.Path(exists=True))
@output_option
@pdf_option
def all_scans(image, container_id, dockerfile, output, pdf_path):
    """Scan a Dockerfile, image, and running container for security misconfigurations."""
    # Run each scan without its own --pdf; a single combined report is written below.
    df_findings, df_skipped = _do_scan_dockerfile(dockerfile, output)
    img_findings, img_skipped = _do_scan(image, output)
    rt_findings, rt_skipped = _do_scan_runtime(container_id, output)

    if pdf_path:
        from containerguard.reporter import render_combined_pdf
        # A scan whose target was not found returns (None, None); skip those sections.
        candidates = [
            (f"Dockerfile — {dockerfile}", df_findings, df_skipped),
            (f"Image — {image}", img_findings, img_skipped),
            (f"Runtime — {container_id}", rt_findings, rt_skipped),
        ]
        sections = [(h, f, s) for h, f, s in candidates if f is not None]
        render_combined_pdf(sections, pdf_path, title="ContainerGuard Combined Report")
        click.echo(f"Combined PDF report written to: {pdf_path}")

from containerguard.hardener import harden

@cli.command("harden")
@click.argument("dockerfile", type=click.Path(exists=True))
@click.option("--output", type=click.Path(), default=None,
              help="Path to write the hardened Dockerfile. Defaults to Dockerfile.hardened in the same directory.")
@click.option("-d", "--print-diff", is_flag=True, default=False,
              help="Print a unified diff between the original and hardened Dockerfiles.")
@pdf_option
def harden_cmd(dockerfile, output, print_diff, pdf_path):
    """Generate a hardened Dockerfile from a vulnerable one."""
    click.echo("Hello from ContainerGuard")
    click.echo(f"Hardening: {dockerfile}")
    harden(dockerfile, output_path=output, print_diff=print_diff, pdf_path=pdf_path)

if __name__ == "__main__":
    cli()
