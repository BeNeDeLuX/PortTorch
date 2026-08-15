#!/usr/bin/env bash
#
# PortTorch scanner installer - Debian (and Debian-derivatives) only for now.
#
# Installs masscan/nmap/gowitness/xfreerdp3/Xvfb/ImageMagick/tesseract,
# gets the porttorch binary (downloaded prebuilt, or built from this
# checkout - see below), grants masscan/nmap raw socket capabilities,
# writes ~porttorch/.config/porttorch/config.yaml, and sets up a systemd
# service running "porttorch serve" so rescans and recurring schedules
# work without a human keeping a terminal open.
#
# Usage: sudo ./install.sh   (run from inside the scanner/ checkout)
#        sudo ./install.sh --rebuild-only   (after a "git pull" - just
#          rebuilds the porttorch binary from the current checkout and
#          restarts the service, skipping the apt-get/gowitness/config steps.
#          Requires a prior full install to already exist.)
#        sudo ./install.sh --from-source   (skip the prebuilt-binary download
#          below even if the checkout is exactly at a released tag, and
#          always build from source instead. Flags can be combined.)
#
# When this checkout's current commit is exactly a "scanner-vX.Y.Z" tag, the
# porttorch binary is downloaded from that tag's GitHub Release instead of
# being built locally (faster, no Go toolchain needed on this host at all) -
# see .github/workflows/scanner-release.yml. Any other checkout state (a
# branch, or commits ahead of the last tag) has no matching release, so this
# always falls back to building from source - it never installs code
# different from what's actually checked out here.

set -euo pipefail

REBUILD_ONLY=false
FORCE_FROM_SOURCE=false
for arg in "$@"; do
  case "$arg" in
    --rebuild-only) REBUILD_ONLY=true ;;
    --from-source) FORCE_FROM_SOURCE=true ;;
    *) echo "unknown argument: $arg (supported: --rebuild-only, --from-source)" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

REQUIRED_GO_VERSION="1.26.5"
SERVICE_USER="porttorch"
SERVICE_HOME="/var/lib/porttorch"
CONFIG_DIR="$SERVICE_HOME/.config/porttorch"
CONFIG_PATH="$CONFIG_DIR/config.yaml"
BIN_PATH="/usr/local/bin/porttorch"
SYSTEMD_UNIT="/etc/systemd/system/porttorch-scanner.service"

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo ./install.sh)"
[[ -f go.mod ]] || die "run this from inside the scanner/ checkout (go.mod not found here)"

if $REBUILD_ONLY; then
  # These all need to already exist from a prior full install - rebuild-only
  # is deliberately just "recompile + restart", not a substitute for it.
  id "$SERVICE_USER" >/dev/null 2>&1 || die "system user '$SERVICE_USER' doesn't exist - run a full install first (without --rebuild-only)"
  [[ -f "$CONFIG_PATH" ]] || die "$CONFIG_PATH doesn't exist - run a full install first (without --rebuild-only)"
  [[ -f "$SYSTEMD_UNIT" ]] || die "$SYSTEMD_UNIT doesn't exist - run a full install first (without --rebuild-only)"
else
  command -v apt-get >/dev/null 2>&1 || die "this installer only supports Debian/Debian-derivatives (apt-get not found)"

  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    case "${ID:-}:${ID_LIKE:-}" in
      *debian*) ;;
      *) warn "this looks like ${PRETTY_NAME:-a non-Debian distro} - only tested on Debian, continuing anyway" ;;
    esac
  fi

  # --- required packages ------------------------------------------------
  # acl (setfacl/getfacl) is what lets the unprivileged $SERVICE_USER
  # write into $BIN_PATH's own directory for self-update - see the ACL
  # grant further below for why this can't just be a chown.
  log "Installing required packages (masscan, nmap, libcap2-bin, acl)"
  apt-get update -qq
  apt-get install -y masscan nmap libcap2-bin curl ca-certificates openssl acl

  # --- optional packages (screenshots/OCR are best-effort scanner features) --
  install_optional() {
    local pkg="$1"
    if apt-get install -y "$pkg"; then
      return 0
    fi
    warn "could not install '$pkg' - the feature that needs it will just be skipped (best-effort, see doctor output at the end)"
    return 0
  }
  log "Installing optional packages (chromium, xfreerdp3, Xvfb, ImageMagick, tesseract)"
  install_optional chromium
  install_optional freerdp3-x11
  install_optional xvfb
  install_optional imagemagick
  install_optional tesseract-ocr
fi

# --- prebuilt-binary fast path (see header comment above) ---------------
release_repo_slug() {
  local url
  url="$(git -c safe.directory="$SCRIPT_DIR" -C "$SCRIPT_DIR" remote get-url origin 2>/dev/null || true)"
  [[ -n "$url" ]] || return 1
  url="${url#git@github.com:}"
  url="${url#https://github.com/}"
  url="${url%.git}"
  [[ "$url" == */* ]] || return 1
  printf '%s' "$url"
}

download_release_binary() {
  local tag="$1" arch="$2" repo bin_url sums_url tmp_bin tmp_sums expected actual
  repo="$(release_repo_slug)" || { warn "couldn't determine GitHub repo from 'git remote get-url origin'"; return 1; }
  bin_url="https://github.com/$repo/releases/download/$tag/porttorch-linux-$arch"
  sums_url="https://github.com/$repo/releases/download/$tag/SHA256SUMS"
  tmp_bin="$(mktemp)"; tmp_sums="$(mktemp)"
  if ! curl -fsSL "$bin_url" -o "$tmp_bin"; then
    rm -f "$tmp_bin" "$tmp_sums"; return 1
  fi
  if ! curl -fsSL "$sums_url" -o "$tmp_sums"; then
    warn "downloaded $tag binary but couldn't fetch its SHA256SUMS - refusing to install an unverified binary"
    rm -f "$tmp_bin" "$tmp_sums"; return 1
  fi
  expected="$(awk -v f="porttorch-linux-$arch" '$2 == f {print $1}' "$tmp_sums")"
  actual="$(sha256sum "$tmp_bin" | awk '{print $1}')"
  if [[ -z "$expected" || "$expected" != "$actual" ]]; then
    warn "checksum mismatch for $tag's porttorch-linux-$arch - refusing to install it"
    rm -f "$tmp_bin" "$tmp_sums"; return 1
  fi
  install -m 755 "$tmp_bin" "$BIN_PATH"
  rm -f "$tmp_bin" "$tmp_sums"
  return 0
}

BUILT_FROM_SOURCE=true
if ! $FORCE_FROM_SOURCE; then
  release_tag="$(git -c safe.directory="$SCRIPT_DIR" -C "$SCRIPT_DIR" describe --tags --exact-match --match 'scanner-v*' 2>/dev/null || true)"
  if [[ -n "$release_tag" ]]; then
    case "$(uname -m)" in
      x86_64) release_arch=amd64 ;;
      aarch64) release_arch=arm64 ;;
      *) release_arch="" ;;
    esac
    if [[ -n "$release_arch" ]]; then
      log "Checkout is exactly at release $release_tag - downloading the prebuilt $release_arch binary instead of building from source"
      if download_release_binary "$release_tag" "$release_arch"; then
        BUILT_FROM_SOURCE=false
      else
        warn "prebuilt binary download failed - falling back to building from source"
      fi
    fi
  fi
fi

# gowitness (below) always needs a Go toolchain on a full install, regardless
# of whether porttorch itself was just downloaded.
if $BUILT_FROM_SOURCE || ! $REBUILD_ONLY; then
  # --- Go toolchain (needed to build; not needed at runtime afterward) ---
  # Checked both on $PATH and at /usr/local/go/bin directly - a prior run of
  # this script put it there, but that directory is only added to *this*
  # process's PATH below, not persisted anywhere, so plain "command -v go"
  # alone would look for it and always miss it on every re-run.
  need_go_install=true
  go_bin=""
  if command -v go >/dev/null 2>&1; then
    go_bin="$(command -v go)"
  elif [[ -x /usr/local/go/bin/go ]]; then
    go_bin="/usr/local/go/bin/go"
  fi
  if [[ -n "$go_bin" ]]; then
    current_go="$("$go_bin" version | awk '{print $3}' | sed 's/^go//')"
    if [[ "$(printf '%s\n%s\n' "$REQUIRED_GO_VERSION" "$current_go" | sort -V | head -1)" == "$REQUIRED_GO_VERSION" ]]; then
      need_go_install=false
    fi
  fi

  if $need_go_install; then
    case "$(uname -m)" in
      x86_64) go_arch=amd64 ;;
      aarch64) go_arch=arm64 ;;
      *) die "unsupported architecture $(uname -m) for automatic Go install - install Go $REQUIRED_GO_VERSION+ yourself and re-run" ;;
    esac
    log "Installing Go $REQUIRED_GO_VERSION (apt's golang-go is usually too old for this project)"
    tmp_tar="$(mktemp)"
    curl -fsSL "https://go.dev/dl/go${REQUIRED_GO_VERSION}.linux-${go_arch}.tar.gz" -o "$tmp_tar"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$tmp_tar"
    rm -f "$tmp_tar"
  else
    log "Go $current_go already satisfies the $REQUIRED_GO_VERSION+ requirement, skipping Go install"
  fi
  export PATH="/usr/local/go/bin:$PATH"
fi

# --- build the scanner binary (skipped if downloaded above) --------------
if $BUILT_FROM_SOURCE; then
  log "Building porttorch -> $BIN_PATH"
  go build -o "$BIN_PATH" ./cmd/scanner
  chmod 755 "$BIN_PATH"
fi

# The systemd service runs as the unprivileged $SERVICE_USER (setcap on
# masscan/nmap - not the porttorch binary's own uid - is what grants raw-
# socket access), but self-update (scanner/internal/updater) needs that
# user to be able to replace $BIN_PATH at runtime. Chowning the binary
# file alone is NOT sufficient for this - a real, confirmed-in-production
# gap: self-update's atomic replacement stages a temp file and
# os.Renames it into place, which needs write access to $BIN_PATH's
# *containing directory*, not just ownership of the file itself.
# /usr/local/bin is root:root 0755 on every stock Debian install, so
# $SERVICE_USER could never create anything there no matter how the
# binary file itself was chowned - every self-update attempt failed with
# "binary or directory not writable" until this was added, on every
# installation, not just ones that predate some earlier fix.
#
# grant_bin_dir_access uses a POSIX ACL rather than chowning/chmodding
# $BIN_DIR itself: /usr/local/bin is a shared system directory other
# packages/admins also install into, and broadly opening it up (group-
# write, or reassigning its owner) would let this one low-privilege
# service account overwrite unrelated binaries placed there by anyone
# else. setfacl grants exactly $SERVICE_USER, and nothing else, write+
# execute on this one directory - inspect with `getfacl "$BIN_DIR"`.
BIN_DIR="$(dirname "$BIN_PATH")"
grant_bin_dir_access() {
  if ! command -v setfacl >/dev/null 2>&1; then
    # Only reachable via --rebuild-only against a pre-ACL-fix install,
    # where the required-packages apt-get pass above (which now includes
    # acl) never ran. A single small package here is cheap enough not to
    # need its own --rebuild-only opt-out.
    apt-get install -y acl || { warn "couldn't install 'acl' - self-update won't be able to write to $BIN_DIR ('sudo setfacl -m u:$SERVICE_USER:rwx $BIN_DIR' manually, or it'll keep failing)"; return 0; }
  fi
  setfacl -m "u:$SERVICE_USER:rwx" "$BIN_DIR"
}

# Covers both the from-source-build and downloaded-release paths above in
# one place. On a fresh full install $SERVICE_USER doesn't exist yet at
# this point (created further below), so this whole block is a no-op
# here and the equivalent block after user creation below covers it
# instead; on --rebuild-only (which requires the user to already exist,
# checked up front) this is the only place that runs, which is exactly
# what makes --rebuild-only alone sufficient to fix an existing
# deployment that predates this fix.
if id "$SERVICE_USER" >/dev/null 2>&1; then
  chown "$SERVICE_USER:$SERVICE_USER" "$BIN_PATH"
  grant_bin_dir_access
fi

if $REBUILD_ONLY; then
  log "--rebuild-only: skipping gowitness rebuild, setcap, user/config/systemd-unit setup"
else
  # --- build gowitness (not packaged for Debian, installed straight from source) --
  log "Building gowitness -> /usr/local/bin/gowitness"
  if ! GOBIN=/usr/local/bin go install github.com/sensepost/gowitness@latest; then
    warn "gowitness build failed - HTTP(S) screenshots will be skipped (best-effort, see doctor output at the end)"
  fi

  # --- raw socket capabilities for masscan/nmap ---------------------------
  log "Granting cap_net_raw,cap_net_admin to masscan/nmap"
  setcap cap_net_raw,cap_net_admin+eip "$(command -v masscan)"
  setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)"

  # --- dedicated system user for the systemd service ----------------------
  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    log "Creating system user '$SERVICE_USER' ($SERVICE_HOME)"
    useradd --system --create-home --home-dir "$SERVICE_HOME" --shell /usr/sbin/nologin "$SERVICE_USER"
  fi
  mkdir -p "$CONFIG_DIR"

  # Fresh-install counterpart of the chown+ACL block right after the
  # build step above: $SERVICE_USER didn't exist yet at that point on a
  # truly fresh install, so this is what actually applies both there (a
  # no-op re-application on every other path that reaches here).
  chown "$SERVICE_USER:$SERVICE_USER" "$BIN_PATH"
  grant_bin_dir_access

  # --- config.yaml ----------------------------------------------------------
  # sed replacement values come from the operator running this installer as
  # root, not from an untrusted remote source - still escaped defensively in
  # case a URL/token happens to contain a sed-special character.
  escape_sed_repl() { printf '%s' "$1" | sed -e 's/[\/&|]/\\&/g'; }

  if [[ -f "$CONFIG_PATH" ]]; then
    warn "$CONFIG_PATH already exists, leaving it untouched (delete it first if you want to reconfigure interactively)"
  else
    cp config.example.yaml "$CONFIG_PATH"

    echo
    log "Scanner registration (create this first under Dashboard -> Scanner Agents -> Create, if you haven't yet)"
    read -rp "Webserver URL (e.g. https://porttorch.internal:443): " WEBSERVER_URL
    read -rsp "API key: " API_KEY; echo
    read -rp "Path to the webserver's server-cert.pem, or leave empty to trust it insecurely (not recommended outside quick tests): " CA_CERT_PATH

    sed -i "s|^webserverUrl:.*|webserverUrl: \"$(escape_sed_repl "$WEBSERVER_URL")\"|" "$CONFIG_PATH"
    sed -i "s|^apiKey:.*|apiKey: \"$(escape_sed_repl "$API_KEY")\"|" "$CONFIG_PATH"

    if [[ -n "$CA_CERT_PATH" ]]; then
      sed -i "s|^# serverCaCertPath:.*|serverCaCertPath: \"$(escape_sed_repl "$CA_CERT_PATH")\"|" "$CONFIG_PATH"
    else
      sed -i "s|^insecureSkipVerify:.*|insecureSkipVerify: true|" "$CONFIG_PATH"
    fi

    # controlApiToken authenticates the scanner's own "serve" REST API -
    # nothing the operator needs to choose themselves, so generate it.
    CONTROL_TOKEN="$(openssl rand -hex 32)"
    sed -i "s|^controlApiToken:.*|controlApiToken: \"$CONTROL_TOKEN\"|" "$CONFIG_PATH"
  fi

  chown -R "$SERVICE_USER:$SERVICE_USER" "$SERVICE_HOME"
  chmod 600 "$CONFIG_PATH"

  # --- systemd service --------------------------------------------------
  log "Installing systemd service porttorch-scanner.service"
  cat > "$SYSTEMD_UNIT" <<EOF
[Unit]
Description=PortTorch scanner (serve mode - polls for rescans/schedules)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$BIN_PATH serve --config $CONFIG_PATH
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$(basename "$SYSTEMD_UNIT")"
fi

log "Restarting porttorch-scanner.service"
systemctl restart "$(basename "$SYSTEMD_UNIT")"

# --- summary ------------------------------------------------------------
echo
log "Running 'porttorch doctor' to confirm everything is set up correctly"
sudo -u "$SERVICE_USER" "$BIN_PATH" doctor --config "$CONFIG_PATH" || true

echo
log "Done. porttorch-scanner.service is enabled and running as user '$SERVICE_USER'."
echo "  Logs:          journalctl -u porttorch-scanner -f"
echo "  Config:        $CONFIG_PATH"
echo "  Manual scan:   sudo -u $SERVICE_USER $BIN_PATH scan --config $CONFIG_PATH --target <ip/range> --ports <spec>"
echo "  Re-run this script any time (e.g. after 'git pull') to rebuild and restart the service -"
echo "  add --rebuild-only to skip the apt-get/gowitness/config/systemd steps and just do that."
if $BUILT_FROM_SOURCE; then
  echo "  This install was built from source. Checking out a 'scanner-vX.Y.Z' tag"
  echo "  next time downloads a prebuilt binary instead (add --from-source to opt out)."
else
  echo "  This install used the prebuilt binary from release $release_tag."
fi
