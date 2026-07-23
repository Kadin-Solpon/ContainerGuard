import re
import os
import difflib
from containerguard.checks.dockerfile_checks import (
    run_all_dockerfile_checks,
    SENSITIVE_PATTERNS,
)


def _fix_base_pinning(lines, findings):
    """CG-006b: Annotate the FROM line with a TODO — we can't auto-pin without querying the registry."""
    if not any(f["id"] == "CG-006b" for f in findings):
        return lines
    result = []
    for line in lines:
        if re.match(r'^\s*FROM\s+', line, re.IGNORECASE):
            result.append(
                line.rstrip() +
                "  # TODO [CG-006b]: Pin to a digest. "
                "Run: docker pull <image> && "
                "docker inspect <image> --format '{{.RepoDigests}}'\n"
            )
        else:
            result.append(line)
    return result


def _fix_secrets(lines, findings):
    """CG-002b: Replace hardcoded ENV secrets with a comment explaining the removal."""
    if not any(f["id"] == "CG-002b" for f in findings):
        return lines
    result = []
    for line in lines:
        match = re.match(r'^\s*ENV\s+(\w+)[=\s](\S+)', line, re.IGNORECASE)
        if match and SENSITIVE_PATTERNS.search(match.group(1)):
            name = match.group(1)
            result.append(
                f"# REMOVED [CG-002b]: ENV {name} — hardcoded secret baked into the image. "
                f"Anyone with image access can read it via docker inspect. "
                f"Pass at runtime via --env-file .env or a secrets manager.\n"
            )
        else:
            result.append(line)
    return result


def _fix_expose_22(lines, findings):
    """CG-008b: Replace EXPOSE 22 with a comment explaining the removal."""
    if not any(f["id"] == "CG-008b" for f in findings):
        return lines
    result = []
    for line in lines:
        if re.match(r'^\s*EXPOSE\s+.*\b22(/tcp|/udp)?\b', line, re.IGNORECASE):
            result.append(
                "# REMOVED [CG-008b]: EXPOSE 22 — SSH port exposes unnecessary attack surface. "
                "A web app has no legitimate reason to expose SSH. "
                "Only expose ports your app actually needs.\n"
            )
        else:
            result.append(line)
    return result


def _fix_user(lines, findings):
    """CG-001b: Insert a non-root user directive before CMD."""
    if not any(f["id"] == "CG-001b" for f in findings):
        return lines
    result = []
    for line in lines:
        if re.match(r'^\s*CMD\s+', line, re.IGNORECASE):
            result.append("RUN useradd -m appuser\n")
            result.append("USER appuser\n")
        result.append(line)
    return result


def _fix_healthcheck(lines, findings):
    """CG-005b: Insert a HEALTHCHECK directive before CMD."""
    if not any(f["id"] == "CG-005b" for f in findings):
        return lines
    result = []
    for line in lines:
        if re.match(r'^\s*CMD\s+', line, re.IGNORECASE):
            result.append(
                "HEALTHCHECK --interval=30s --timeout=3s "
                "CMD curl -f http://localhost:5000/health || exit 1\n"
            )
        result.append(line)
    return result

def _print_diff(original_lines, hardened_lines, original_path, output_path):
    """Print a unified diff between the original and hardened Dockerfiles."""
    diff = list(difflib.unified_diff(
        original_lines,
        hardened_lines,
        fromfile=original_path,
        tofile=output_path,
        lineterm="",
    ))

    if not diff:
        print("No changes produced.")
        return

    print("\n── Diff ───────────────────────────────────")
    for line in diff:
        # Color the diff manually without requiring rich
        if line.startswith("+") and not line.startswith("+++"):
            print(f"\033[32m{line}\033[0m")   # green
        elif line.startswith("-") and not line.startswith("---"):
            print(f"\033[31m{line}\033[0m")   # red
        elif line.startswith("@@"):
            print(f"\033[36m{line}\033[0m")   # cyan
        else:
            print(line)

def harden(dockerfile_path, output_path=None, print_diff=False, pdf_path=None):
    """
    Read a Dockerfile, fix all detected findings, write Dockerfile.hardened,
    and optionally print a unified diff. When pdf_path is given, also write a
    PDF report including the findings and the Dockerfile diff. Returns the
    output path, or None if no fixes needed.
    """
    if output_path is None:
        directory = os.path.dirname(os.path.abspath(dockerfile_path))
        output_path = os.path.join(directory, "Dockerfile.hardened")

    findings, skipped = run_all_dockerfile_checks(dockerfile_path)

    if not findings:
        print("No issues found — Dockerfile is already hardened.")
        return None

    print(f"\nApplying {len(findings)} fix(es) to {dockerfile_path}...")

    with open(dockerfile_path) as f:
        original_lines = f.readlines()

    lines = original_lines[:]

    # Removals and replacements first, insertions last.
    # Insertions change list length, which would shift
    # the indices that removals/replacements rely on.
    lines = _fix_expose_22(lines, findings)
    lines = _fix_secrets(lines, findings)
    lines = _fix_base_pinning(lines, findings)
    lines = _fix_user(lines, findings)
    lines = _fix_healthcheck(lines, findings)

    with open(output_path, "w") as f:
        f.writelines(lines)

    print(f"Hardened Dockerfile written to: {output_path}")
    if print_diff:
        _print_diff(original_lines, lines, dockerfile_path, output_path)

    if pdf_path:
        # Imported here so scanning/hardening without --pdf never touches reportlab.
        from containerguard.reporter import render_pdf, build_dockerfile_diff
        diff = build_dockerfile_diff(
            original_lines, lines,
            fromfile=dockerfile_path, tofile=output_path,
        )
        render_pdf(
            findings, pdf_path, skipped=skipped,
            title="Dockerfile Hardening Report", dockerfile_diff=diff,
        )
        print(f"PDF report written to: {pdf_path}")

    return output_path
