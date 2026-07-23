import docker
from docker.errors import NotFound, ImageNotFound, DockerException
from containerguard.checks.image_checks import run_all_checks
from containerguard.checks.runtime_checks import run_all_runtime_checks
from containerguard.checks.dockerfile_checks import run_all_dockerfile_checks
from containerguard.reporter import emit_findings, render_pdf


def get_client():
    """Connect to the Docker daemon via socket."""
    try:
        client = docker.from_env()
        client.ping()
        return client
    except DockerException:
        print("Error: Docker is not running. Start Docker Desktop first.")
        exit(1)


def get_image_attrs(image_name, quiet=False):
    """
    Pull image metadata and parse docker inspect output into a dict.
    Equivalent to running: docker inspect <image>
    """
    client = get_client()
    try:
        image = client.images.get(image_name)
        attrs = image.attrs

        if not quiet:
            print(f"\nImage:      {image_name}")
            print(f"ID:         {image.short_id}")
            print(f"Tags:       {image.tags}")
            print(f"Created:    {attrs['Created']}")
            print(f"Size:       {round(attrs['Size'] / 1e6, 1)} MB")
            print(f"OS:         {attrs['Os']}")
            print(f"User:       {attrs['Config'].get('User') or 'root (not set)'}")
            print(f"Exposed:    {list(attrs['Config'].get('ExposedPorts', {}).keys())}")
            print(f"Env:        {attrs['Config'].get('Env', [])}")
            print(f"Healthcheck:{attrs['Config'].get('Healthcheck', None)}")

        return attrs

    except ImageNotFound:
        print(f"Image '{image_name}' not found locally.")
        print(f"Try: docker pull {image_name}")
        return None


def get_container_attrs(container_id, quiet=False):
    """
    Pull live container metadata and parse docker inspect output into a dict.
    Equivalent to running: docker inspect <container>
    """
    client = get_client()
    try:
        container = client.containers.get(container_id)
        attrs = container.attrs

        if not quiet:
            print(f"\nContainer:  {container_id}")
            print(f"Image:      {attrs['Config']['Image']}")
            print(f"Status:     {attrs['State']['Status']}")
            print(f"Started:    {attrs['State']['StartedAt']}")
            print(f"User:       {attrs['Config']['User'] or 'root (not set)'}")
            print(f"Privileged: {attrs['HostConfig']['Privileged']}")
            print(f"ReadOnly:   {attrs['HostConfig']['ReadonlyRootfs']}")
            print(f"Memory:     {attrs['HostConfig']['Memory']} (0 = unlimited)")
            print(f"CPUs:       {attrs['HostConfig']['NanoCpus']} (0 = unlimited)")
            print(f"CapAdd:     {attrs['HostConfig']['CapAdd']}")
            print(f"CapDrop:    {attrs['HostConfig']['CapDrop']}")
            print(f"Mounts:     {[m['Source'] for m in attrs['Mounts']]}")

        return attrs

    except NotFound:
        print(f"Container '{container_id}' not found. Is it running?")
        return None

def _maybe_pdf(findings, skipped, title, pdf_path):
    """Render a PDF report when a path was requested."""
    if not pdf_path:
        return
    render_pdf(findings, pdf_path, skipped=skipped, title=title)
    print(f"PDF report written to: {pdf_path}")


def scan_dockerfile(dockerfile_path, output="table", pdf_path=None):
    """Entry point for Dockerfile-only scanning."""
    findings, skipped = run_all_dockerfile_checks(dockerfile_path)
    emit_findings(findings, skipped, title="Dockerfile Scan Findings", output=output)
    _maybe_pdf(findings, skipped, "Dockerfile Scan Report", pdf_path)
    return findings, skipped

def scan_image(image_name, output="table", pdf_path=None):
    """Entry point for static image scanning."""
    attrs = get_image_attrs(image_name, quiet=(output == "json"))
    if not attrs:
        return None, None

    findings, skipped = run_all_checks(attrs)

    emit_findings(findings, skipped, title="Image Scan Findings", output=output)
    _maybe_pdf(findings, skipped, f"Image Scan Report — {image_name}", pdf_path)
    return findings, skipped

def scan_runtime(container_id, output="table", pdf_path=None):
    """Entry point for live container scanning."""
    attrs = get_container_attrs(container_id, quiet=(output == "json"))
    if not attrs:
        return None, None

    findings, skipped = run_all_runtime_checks(attrs)
    emit_findings(findings, skipped, title="Runtime Scan Findings", output=output)
    _maybe_pdf(findings, skipped, f"Runtime Scan Report — {container_id}", pdf_path)
    return findings, skipped
