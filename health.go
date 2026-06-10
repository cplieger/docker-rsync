package main

import "github.com/cplieger/health"

// healthMarkerPath is where the health marker file lives. Docker's
// HEALTHCHECK re-invokes the binary with the `health` subcommand, which
// stats this path. /tmp is conventional because read-only containers
// mount it as tmpfs.
const healthMarkerPath = health.DefaultPath
