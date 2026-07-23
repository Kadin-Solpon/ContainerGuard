import re

SENSITIVE_PATTERNS = re.compile(
    r'(PASSWORD|SECRET|API_KEY|TOKEN|CREDENTIAL|PRIVATE_KEY|PWD|PASSWD)',
    re.IGNORECASE
)


def check_root_user(attrs):
    """CG-001 CRITICAL: Container runs as root (no USER directive)."""
    user = attrs.get("Config", {}).get("User", "")
    if not user or user in ("root", "0"):
        return {
            "id":          "CG-001",
            "severity":    "CRITICAL",
            "title":       "Running as root",
            "description": "No USER directive in Dockerfile. Container runs as root (UID 0).",
            "remediation": "Add USER appuser to your Dockerfile after creating the user with RUN useradd -m appuser.",
            "cis_rule":    "4.1",
        }
    return None


def check_hardcoded_secrets(attrs):
    """CG-002 CRITICAL: Sensitive value hardcoded in ENV."""
    env_vars = attrs.get("Config", {}).get("Env", []) or []
    findings = []
    for var in env_vars:
        parts = var.split("=", 1)
        if len(parts) < 2:
            continue
        name, value = parts
        if SENSITIVE_PATTERNS.search(name) and value:
            findings.append({
                "id":          "CG-002",
                "severity":    "CRITICAL",
                "title":       f"Hardcoded secret in ENV: {name}",
                "description": f"ENV variable '{name}' appears to contain a secret baked into the image. "
                               f"Visible in plaintext via docker inspect.",
                "remediation": "Remove from Dockerfile. Pass at runtime via --env-file .env or a secrets manager.",
                "cis_rule":    "4.10",
            })
    return findings


def check_latest_tag(attrs):
    """CG-006 MEDIUM: Image uses :latest tag, or has been pushed/pulled without a pinned digest."""
    repo_tags = attrs.get("RepoTags", []) or []
    repo_digests = attrs.get("RepoDigests", []) or []

    for tag in repo_tags:
        if tag.endswith(":latest"):
            return {
                "id":          "CG-006",
                "severity":    "MEDIUM",
                "title":       "Image tagged :latest",
                "description": f"Image tag '{tag}' is unpinned. :latest is a moving target — "
                               f"rebuilds may silently pull a different version.",
                "remediation": "Pin to a specific version digest e.g. python:3.13@sha256:abc123...",
                "cis_rule":    "4.11",
            }

    # Only evaluate digest-pinning if this image has actually interacted
    # with a registry (i.e. it's been pushed or pulled at some point).
    # A purely local, never-pushed build has no RepoDigests and that's
    # expected — not a finding.
    if repo_tags and not repo_digests:
        return {
            "id":          "CG-006",
            "severity":    "MEDIUM",
            "title":       "Image not pinned to a digest",
            "description": "This image has a registry-associated tag but no confirmed digest. "
                           "Image reproducibility at distribution time is not guaranteed.",
            "remediation": "Reference this image elsewhere by its digest, e.g. "
                           "myapp@sha256:abc123..., not by a mutable tag.",
            "cis_rule":    "4.11",
        }

    return None

def check_exposed_port_22(attrs):
    """CG-008 HIGH: SSH port 22 exposed in Dockerfile."""
    exposed = attrs.get("Config", {}).get("ExposedPorts", {}) or {}
    if "22/tcp" in exposed or "22/udp" in exposed:
        return {
            "id":          "CG-008",
            "severity":    "HIGH",
            "title":       "SSH port 22 exposed",
            "description": "Port 22 (SSH) is exposed in the Dockerfile. A web app has no legitimate "
                           "reason to expose SSH. Opens attack surface for brute force and SSH exploits.",
            "remediation": "Remove EXPOSE 22 from Dockerfile. Only expose ports your app actually needs.",
            "cis_rule":    "5.9",
        }
    return None


def check_missing_healthcheck(attrs):
    """CG-005 LOW: No HEALTHCHECK defined in Dockerfile."""
    healthcheck = attrs.get("Config", {}).get("Healthcheck", None)
    if not healthcheck:
        return {
            "id":          "CG-005",
            "severity":    "LOW",
            "title":       "No HEALTHCHECK defined",
            "description": "Docker cannot determine if the container is healthy or just running. "
                           "Unhealthy containers won't be restarted automatically.",
            "remediation": "Add HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:5000/health || exit 1",
            "cis_rule":    "4.6",
        }
    return None

def run_all_checks(attrs):
    """Run all image checks and return a flat list of findings."""
    findings = []
    skipped = []

    checks = [
        check_root_user,
        check_latest_tag,
        check_exposed_port_22,
        check_missing_healthcheck,
    ]

    for check in checks:
        result = check(attrs)
        if result:
            findings.append(result)

    # check_hardcoded_secrets returns a list not a single finding
    findings.extend(check_hardcoded_secrets(attrs))

    return findings, skipped
