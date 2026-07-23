# Capabilities that Docker gives every container by default.
# These are acceptable — we don't flag them.
DEFAULT_CAPS = {
    "AUDIT_WRITE",
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "MKNOD",
    "NET_BIND_SERVICE",
    "NET_RAW",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_CHROOT",
}

# Capabilities that are particularly dangerous if explicitly added.
DANGEROUS_CAPS = {
    "ALL",          # grants every capability — worst case
    "NET_ADMIN",    # can reconfigure network interfaces, iptables, routing
    "SYS_ADMIN",    # catch-all: mounts, namespaces, cgroups — near-root
    "SYS_PTRACE",   # can attach to and inspect any process in the container
    "SYS_MODULE",   # can load/unload kernel modules — full kernel access
    "DAC_READ_SEARCH",  # bypass file read permission checks
    "SYS_RAWIO",    # raw I/O access to physical devices
    "NET_BROADCAST", # send broadcast packets — rarely needed
}


def check_privileged(attrs):
    """CG-010 CRITICAL: Container is running in privileged mode."""
    privileged = attrs.get("HostConfig", {}).get("Privileged", False)
    if privileged:
        return {
            "id":          "CG-010",
            "severity":    "CRITICAL",
            "title":       "Container running in privileged mode",
            "description": "The container was started with --privileged, which disables all "
                           "Linux security boundaries. It has access to all host devices, "
                           "can load kernel modules, and can escape the container entirely.",
            "remediation": "Remove --privileged. Grant only the specific capabilities the app "
                           "needs via --cap-add instead.",
            "cis_rule":    "5.4",
        }
    return None


def check_readonly_rootfs(attrs):
    """CG-011 MEDIUM: Container root filesystem is writable."""
    readonly = attrs.get("HostConfig", {}).get("ReadonlyRootfs", False)
    if not readonly:
        return {
            "id":          "CG-011",
            "severity":    "MEDIUM",
            "title":       "Writable root filesystem",
            "description": "The container's root filesystem is writable. If an attacker gets "
                           "code execution, they can modify binaries, install tools, or "
                           "persist changes across container restarts.",
            "remediation": "Start the container with --read-only. Mount specific writable "
                           "paths explicitly via --tmpfs or a named volume for paths the "
                           "app genuinely needs to write to (e.g. /tmp).",
            "cis_rule":    "5.12",
        }
    return None


def check_memory_limit(attrs):
    """CG-012 MEDIUM: No memory limit set on the container."""
    # Docker stores memory in bytes; 0 means unlimited.
    memory = attrs.get("HostConfig", {}).get("Memory", 0)
    if memory == 0:
        return {
            "id":          "CG-012",
            "severity":    "MEDIUM",
            "title":       "No memory limit set",
            "description": "Container has no memory limit (Memory=0, unlimited). A memory leak "
                           "or DoS attack can consume all available host memory, taking down "
                           "other containers and the host itself.",
            "remediation": "Set a memory limit appropriate for the app, e.g. "
                           "--memory=512m in docker run, or mem_limit: 512m in "
                           "docker-compose.yml.",
            "cis_rule":    "5.28",
        }
    return None


def check_cpu_limit(attrs):
    """CG-013 LOW: No CPU limit set on the container."""
    # Docker stores CPU quota in nanocpus; 0 means unlimited.
    nanocpus = attrs.get("HostConfig", {}).get("NanoCpus", 0)
    if nanocpus == 0:
        return {
            "id":          "CG-013",
            "severity":    "LOW",
            "title":       "No CPU limit set",
            "description": "Container has no CPU limit (NanoCpus=0, unlimited). A runaway "
                           "process or CPU-exhaustion attack can starve other containers "
                           "of compute.",
            "remediation": "Set a CPU limit, e.g. --cpus=1.0 in docker run, or "
                           "cpus: '1.0' in docker-compose.yml.",
            "cis_rule":    "5.29",
        }
    return None


def check_network_mode(attrs):
    """CG-014 HIGH: Container uses host network mode."""
    network_mode = attrs.get("HostConfig", {}).get("NetworkMode", "")
    if network_mode == "host":
        return {
            "id":          "CG-014",
            "severity":    "HIGH",
            "title":       "Container uses host network mode",
            "description": "The container shares the host's network namespace (--net=host). "
                           "It can bind to any host port, sniff all host network traffic, "
                           "and bypass Docker's network isolation entirely.",
            "remediation": "Remove --net=host. Let Docker manage a bridge network and "
                           "explicitly publish only the ports your app needs with -p.",
            "cis_rule":    "5.31",
        }
    return None


def check_capabilities(attrs):
    """CG-015 HIGH: Dangerous capabilities explicitly added to the container."""
    host_config = attrs.get("HostConfig", {})
    cap_add = host_config.get("CapAdd") or []
    cap_drop = host_config.get("CapDrop") or []

    findings = []

    # Normalize to uppercase for comparison since Docker returns
    # caps inconsistently (e.g. "net_admin" vs "NET_ADMIN")
    added = {cap.upper() for cap in cap_add}
    dropped = {cap.upper() for cap in cap_drop}

    # Flag any dangerous cap that was explicitly added
    dangerous_added = added & DANGEROUS_CAPS
    for cap in sorted(dangerous_added):
        findings.append({
            "id":          "CG-015",
            "severity":    "HIGH",
            "title":       f"Dangerous capability explicitly added: {cap}",
            "description": f"The container was started with --cap-add {cap}. This capability "
                           f"significantly expands what the container can do on the host.",
            "remediation": f"Remove --cap-add {cap}. If the app genuinely needs it, document "
                           f"exactly why in your threat model.",
            "cis_rule":    "5.3",
        })

    # Separately flag if no capabilities are dropped at all —
    # best practice is --cap-drop ALL then add back only what's needed
    if not dropped:
        findings.append({
            "id":          "CG-016",
            "severity":    "MEDIUM",
            "title":       "No capabilities dropped",
            "description": "Container started without --cap-drop ALL. It retains all default "
                           "Docker capabilities. Best practice is to drop everything and "
                           "add back only what the app needs.",
            "remediation": "Add --cap-drop ALL to docker run, then explicitly add back only "
                           "required capabilities with --cap-add. In docker-compose.yml: "
                           "cap_drop: [ALL], cap_add: [NET_BIND_SERVICE].",
            "cis_rule":    "5.3",
        })

    return findings


def run_all_runtime_checks(attrs):
    """Run all runtime checks and return findings and skipped checks."""
    findings = []
    skipped = []

    checks = [
        check_privileged,
        check_readonly_rootfs,
        check_memory_limit,
        check_cpu_limit,
        check_network_mode,
    ]

    for check in checks:
        result = check(attrs)
        if result:
            findings.append(result)

    # check_capabilities returns a list, not a single finding
    findings.extend(check_capabilities(attrs))

    return findings, skipped
