import re

SENSITIVE_PATTERNS = re.compile(
    r'(PASSWORD|SECRET|API_KEY|TOKEN|CREDENTIAL|PRIVATE_KEY|PWD|PASSWD)',
    re.IGNORECASE
)


def check_dockerfile_base_pinned(dockerfile_path):
    """CG-006b MEDIUM: Dockerfile FROM line uses a mutable tag instead of a digest."""
    try:
        with open(dockerfile_path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        return None

    for line in lines:
        match = re.match(r'^\s*FROM\s+(\S+)', line, re.IGNORECASE)
        if match:
            ref = match.group(1)
            if "@sha256:" not in ref:
                return {
                    "id":          "CG-006b",
                    "severity":    "MEDIUM",
                    "title":       "Dockerfile base image not pinned by digest",
                    "description": f"FROM line references '{ref}', a mutable tag. "
                                   f"Rebuilding later may silently pull different content.",
                    "remediation": "Pin with FROM <image>@sha256:<digest>. "
                                   "Get the digest via `docker pull <image>` then "
                                   "`docker inspect --format '{{.RepoDigests}}' <image>`.",
                    "cis_rule":    "4.11",
                }
    return None


def check_dockerfile_root_user(dockerfile_path):
    """CG-001b CRITICAL: No non-root USER directive found in Dockerfile."""
    try:
        with open(dockerfile_path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        return None

    for line in lines:
        match = re.match(r'^\s*USER\s+(\S+)', line, re.IGNORECASE)
        if match:
            user = match.group(1).lower()
            if user not in ("root", "0"):
                return None
    return {
        "id":          "CG-001b",
        "severity":    "CRITICAL",
        "title":       "No USER directive in Dockerfile",
        "description": "No USER directive found. Container will run as root (UID 0).",
        "remediation": "Add USER appuser after RUN useradd -m appuser.",
        "cis_rule":    "4.1",
    }


def check_dockerfile_secrets(dockerfile_path):
    """CG-002b CRITICAL: Hardcoded secrets in ENV directive."""
    try:
        with open(dockerfile_path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        return []

    findings = []
    for line in lines:
        match = re.match(r'^\s*ENV\s+(\w+)[=\s](\S+)', line, re.IGNORECASE)
        if match:
            name, value = match.group(1), match.group(2)
            if SENSITIVE_PATTERNS.search(name) and value:
                findings.append({
                    "id":          "CG-002b",
                    "severity":    "CRITICAL",
                    "title":       f"Hardcoded secret in ENV: {name}",
                    "description": f"ENV variable '{name}' appears to contain a secret "
                                   f"baked into the Dockerfile. Visible to anyone with "
                                   f"access to the image.",
                    "remediation": "Remove from Dockerfile. Pass at runtime via "
                                   "--env-file .env or a secrets manager.",
                    "cis_rule":    "4.10",
                })
    return findings


def check_dockerfile_expose_22(dockerfile_path):
    """CG-008b HIGH: SSH port 22 exposed in Dockerfile."""
    try:
        with open(dockerfile_path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        return None

    for line in lines:
        if re.match(r'^\s*EXPOSE\s+.*\b22(/tcp|/udp)?\b', line, re.IGNORECASE):
            return {
                "id":          "CG-008b",
                "severity":    "HIGH",
                "title":       "SSH port 22 exposed in Dockerfile",
                "description": "Port 22 (SSH) is exposed. A web app has no legitimate "
                               "reason to expose SSH. Opens attack surface for brute "
                               "force and SSH exploits.",
                "remediation": "Remove EXPOSE 22 from Dockerfile. Only expose ports "
                               "your app actually needs.",
                "cis_rule":    "5.9",
            }
    return None


def check_dockerfile_healthcheck(dockerfile_path):
    """CG-005b LOW: No HEALTHCHECK directive in Dockerfile."""
    try:
        with open(dockerfile_path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        return None

    for line in lines:
        if re.match(r'^\s*HEALTHCHECK\s+', line, re.IGNORECASE):
            return None

    return {
        "id":          "CG-005b",
        "severity":    "LOW",
        "title":       "No HEALTHCHECK in Dockerfile",
        "description": "No HEALTHCHECK directive found. Docker cannot determine if "
                       "the container is healthy or just running.",
        "remediation": "Add HEALTHCHECK --interval=30s --timeout=3s "
                       "CMD curl -f http://localhost:5000/health || exit 1",
        "cis_rule":    "4.6",
    }


def run_all_dockerfile_checks(dockerfile_path):
    """Run all Dockerfile-source checks and return findings and skipped."""
    findings = []
    skipped = []

    checks = [
        check_dockerfile_base_pinned,
        check_dockerfile_root_user,
        check_dockerfile_expose_22,
        check_dockerfile_healthcheck,
    ]

    for check in checks:
        result = check(dockerfile_path)
        if result:
            findings.append(result)

    findings.extend(check_dockerfile_secrets(dockerfile_path))

    return findings, skipped
