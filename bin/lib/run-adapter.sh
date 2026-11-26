#!/bin/sh
# run-adapter.sh -- the adapter wrapper: reads the engine-rendered env file
# (mode 600, ro-bound) INSIDE the jail, so the credential never rides the
# host-visible bwrap argv (F5), then execs the adapter argv.
ENVFILE=/w/compiled/adapter.env
[ -r "$ENVFILE" ] || { echo "run-adapter: VOID, no $ENVFILE" >&2; exit 2; }
. "$ENVFILE"
exec "$@"
