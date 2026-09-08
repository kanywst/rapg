// Package version carries the version rapg reports at runtime.
package version

// Version is overwritten at build time with the git tag via
// -ldflags -X. Builds that skip that (go install, go run, a plain
// go build) keep reporting "dev".
var Version = "dev"
