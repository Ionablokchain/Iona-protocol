#!/usr/bin/env bash
set -euo pipefail

# Default values
ACTION="apply"
IFACE=""
NETEM_ARGS="delay 200ms 50ms loss 5%"

# Function to display help
show_help() {
    cat <<EOF
Usage: $0 [options] [action] [interface] [netem_args...]

Apply, remove, or show network emulation (netem) settings on a network interface.

Actions:
  apply                 Apply netem settings (default).
  remove                Remove netem settings from the interface.
  show                  Show current qdisc settings on the interface.

Options:
  -h, --help            Display this help message.

Arguments:
  interface             Network interface (e.g., eth0). If not provided, you will be prompted.
  netem_args            Netem parameters (e.g., "delay 200ms 50ms loss 5% rate 1mbit").
                        Default: "delay 200ms 50ms loss 5%"

Examples:
  $0 eth0                                      # Apply default netem on eth0
  $0 apply eth0 "delay 100ms loss 10%"         # Custom parameters
  $0 remove eth0                               # Remove netem from eth0
  $0 show eth0                                 # Show current settings

Note: This script must be run as root (use sudo).
EOF
}

# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "Error: Unknown option $1"
            show_help
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

# Determine action (first positional argument)
if [[ $# -gt 0 ]] && [[ "$1" =~ ^(apply|remove|show)$ ]]; then
    ACTION="$1"
    shift
fi

# Determine interface (second positional argument or prompt)
if [[ $# -gt 0 ]]; then
    IFACE="$1"
    shift
else
    read -p "Enter network interface (e.g., eth0): " IFACE
fi

# Remaining arguments are netem parameters (only for apply action)
if [[ $ACTION == "apply" ]] && [[ $# -gt 0 ]]; then
    NETEM_ARGS="$*"
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root. Use sudo." >&2
    exit 1
fi

# Check if interface exists
if ! ip link show "$IFACE" > /dev/null 2>&1; then
    echo "Error: Interface $IFACE does not exist." >&2
    exit 1
fi

# Execute requested action
case "$ACTION" in
    apply)
        # Remove existing qdisc to avoid conflicts
        tc qdisc del dev "$IFACE" root 2>/dev/null || true
        # Apply new netem settings
        if tc qdisc add dev "$IFACE" root netem $NETEM_ARGS; then
            echo "Applied netem on $IFACE: $NETEM_ARGS"
        else
            echo "Error: Failed to apply netem on $IFACE." >&2
            exit 1
        fi
        ;;
    remove)
        if tc qdisc del dev "$IFACE" root 2>/dev/null; then
            echo "Removed netem from $IFACE."
        else
            echo "No netem settings found on $IFACE or removal failed." >&2
            exit 1
        fi
        ;;
    show)
        tc qdisc show dev "$IFACE"
        ;;
    *)
        echo "Error: Invalid action '$ACTION'" >&2
        exit 1
        ;;
esac
