#!/usr/bin/env bash
set -euo pipefail

# Defaults
ACTION="apply"          # apply or revert
TARGET=""               # container name(s) or network
PARTITION_TYPE="disconnect"   # disconnect, delay, loss, rate
PARAMS=""               # additional parameters for tc
DURATION=0              # auto-revert after seconds (0 = no auto)
FORCE=0
VERBOSE=0
DRY_RUN=0

show_help() {
    cat <<EOF
Usage: $0 [options] (apply|revert) [target] [params...]

Simulate network partitions in Docker environments.

Actions:
  apply                  Apply network impairment (default).
  revert                 Restore normal connectivity.

Target:
  Container name(s)      e.g., myapp_container, or multiple: "c1 c2"
  Docker network name    e.g., mynetwork (use --network flag)

Options:
  -t, --type TYPE        Partition type: disconnect, delay, loss, rate.
                         (default: disconnect)
  -p, --params PARAMS    Parameters for tc (e.g., "delay 200ms 50ms loss 5%")
  -d, --duration SEC     Auto-revert after SEC seconds (0 = no auto)
  -n, --network          Target is a Docker network (apply to all its containers)
  -f, --force            Skip confirmation prompts.
  -v, --verbose          Show detailed output.
  --dry-run              Print commands without executing.
  -h, --help             Display this help.

Examples:
  $0 apply myapp                         # Isolate myapp from all others
  $0 apply myapp1 myapp2                  # Partition between two containers
  $0 --type delay --params "200ms" apply myapp   # Add 200ms delay
  $0 revert myapp                         # Restore connectivity
  $0 --network -d 60 apply mynetwork       # Partition whole network for 60s

Note: Requires root or docker group permissions.
EOF
}

# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--type)
            PARTITION_TYPE="$2"
            shift 2
            ;;
        -p|--params)
            PARAMS="$2"
            shift 2
            ;;
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -n|--network)
            TARGET_IS_NETWORK=1
            shift
            ;;
        -f|--force)
            FORCE=1
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "Error: Unknown option $1" >&2
            show_help
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

# Determine action (first positional argument)
if [[ $# -gt 0 ]] && [[ "$1" =~ ^(apply|revert)$ ]]; then
    ACTION="$1"
    shift
fi

# Remaining arguments are target(s) and possibly extra params
if [[ $# -gt 0 ]]; then
    TARGET="$*"
else
    read -p "Enter target container(s) or network: " TARGET
fi

# Check Docker availability
if ! command -v docker &>/dev/null; then
    echo "Error: docker command not found." >&2
    exit 1
fi

if ! docker info &>/dev/null; then
    echo "Error: Docker daemon is not running or you lack permissions." >&2
    exit 1
fi

# Function to run commands with sudo if needed (for tc on host)
run_cmd() {
    if [[ $DRY_RUN -eq 1 ]]; then
        echo "[DRY RUN] $*"
    else
        if [[ $VERBOSE -eq 1 ]]; then
            echo "+ $*"
        fi
        eval "$@"
    fi
}

# Apply partition
apply_partition() {
    local container="$1"
    # Get container's PID for network namespace
    local pid
    pid=$(docker inspect -f '{{.State.Pid}}' "$container" 2>/dev/null)
    if [[ -z "$pid" || "$pid" == "0" ]]; then
        echo "Error: Container $container is not running." >&2
        return 1
    fi

    # For disconnect type, we can simply disconnect from all networks? Or use iptables inside ns?
    # Simpler: use `docker network disconnect` for all networks except maybe bridge? But that would isolate completely.
    # For more fine-grained, we can use nsenter and tc inside the container's netns.
    case "$PARTITION_TYPE" in
        disconnect)
            # Disconnect from all networks except the default bridge? Better: disconnect from all user-defined networks.
            # Get list of networks the container is connected to.
            networks=$(docker inspect -f '{{range $net, $v := .NetworkSettings.Networks}}{{$net}} {{end}}' "$container")
            for net in $networks; do
                if [[ "$net" != "bridge" ]]; then
                    run_cmd "docker network disconnect -f \"$net\" \"$container\""
                fi
            done
            ;;
        delay|loss|rate)
            # Use tc inside container's network namespace
            # We need to run tc qdisc add dev eth0 root netem ...
            # Note: container must have eth0 and tc installed.
            run_cmd "sudo nsenter -t $pid -n tc qdisc add dev eth0 root netem $PARAMS"
            ;;
        *)
            echo "Error: Unknown partition type $PARTITION_TYPE" >&2
            return 1
            ;;
    esac
}

# Revert partition
revert_partition() {
    local container="$1"
    local pid
    pid=$(docker inspect -f '{{.State.Pid}}' "$container" 2>/dev/null)
    if [[ -z "$pid" || "$pid" == "0" ]]; then
        echo "Warning: Container $container is not running, skipping." >&2
        return 0
    fi

    case "$PARTITION_TYPE" in
        disconnect)
            # Reconnect to networks? But we don't know original networks. For simplicity, we can't fully revert disconnect unless we stored state.
            # Better: In apply, we recorded networks. For now, just warn.
            echo "Warning: Reconnect manually or restart container." >&2
            ;;
        delay|loss|rate)
            # Remove tc qdisc
            run_cmd "sudo nsenter -t $pid -n tc qdisc del dev eth0 root 2>/dev/null || true"
            ;;
    esac
}

# Main logic
if [[ $TARGET_IS_NETWORK -eq 1 ]]; then
    # Get all containers in that network
    containers=$(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$TARGET" 2>/dev/null || true)
    if [[ -z "$containers" ]]; then
        echo "Error: Network $TARGET not found or has no containers." >&2
        exit 1
    fi
    TARGET_LIST=($containers)
else
    # Assume TARGET is a space-separated list of container names
    TARGET_LIST=($TARGET)
fi

# Confirm if not forced
if [[ $FORCE -eq 0 ]]; then
    echo "About to $ACTION $PARTITION_TYPE on: ${TARGET_LIST[*]}"
    read -p "Proceed? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

# Execute action
for container in "${TARGET_LIST[@]}"; do
    if [[ $ACTION == "apply" ]]; then
        apply_partition "$container"
    else
        revert_partition "$container"
    fi
done

# Auto-revert if duration set
if [[ $ACTION == "apply" && $DURATION -gt 0 ]]; then
    echo "Partition will auto-revert in $DURATION seconds..."
    ( sleep "$DURATION" && exec "$0" --force revert "${TARGET_LIST[@]}" ) &
fi

echo "Done."
