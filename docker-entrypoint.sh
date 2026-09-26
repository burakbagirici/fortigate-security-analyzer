#!/bin/sh
set -e

# Default to --help when no arguments are provided
if [ $# -eq 0 ]; then
    exec fortigate-analyzer --help
fi

# Support 'ui' subcommand to run Streamlit web interface
if [ "$1" = "ui" ]; then
    shift
    exec streamlit run /app/app.py --server.address=0.0.0.0 --server.port=8501 "$@"
fi

# Pass-through for explicit process commands
if [ "$1" = "streamlit" ] || [ "$1" = "sh" ] || [ "$1" = "bash" ]; then
    exec "$@"
fi

# Forward all other arguments directly to the CLI entrypoint
exec fortigate-analyzer "$@"
