// Package version holds the scanner's own version number - bumped by
// hand on meaningful changes for local/dev builds. Released builds (built
// by .github/workflows/scanner-release.yml from a scanner-v* tag) override
// this at build time via -ldflags "-X .../version.Version=<tag>", which
// only works against a package-level var, not a const.
package version

var Version = "0.17.0"
