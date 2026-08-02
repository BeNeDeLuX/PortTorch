#!/usr/bin/env bash
#
# PortTorch scanner installer - Debian (and Debian-derivatives) only for now.
#
# Installs masscan/nmap/gowitness/xfreerdp3/Xvfb/ImageMagick/tesseract,
# builds the scanner binary from this checkout, grants masscan/nmap raw
# socket capabilities, writes ~porttorch/.config/porttorch/config.yaml,
# and sets up a systemd service running "porttorch serve" so rescans and
# recurring schedules work without a human keeping a terminal open.
#
# Usage: sudo ./install.sh   (run from inside the scanner/ checkout)
#        sudo ./install.sh --rebuild-only   (after a "git pull" - just
#          rebuilds the porttorch binary from the current checkout and
#          restarts the service, skipping the apt-get/Go-toolchain/gowitness/
#          config steps. Requires a prior full install to already exist.)

set -euo pipefail

REBUILD_ONLY=false
if [[ "${1:-}" == "--rebuild-only" ]]; then
  REBUILD_ONLY=true
fi

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
  log "Installing required packages (masscan, nmap, libcap2-bin)"
  apt-get update -qq
  apt-get install -y masscan nmap libcap2-bin curl ca-certificates openssl

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

# --- build the scanner binary -------------------------------------------
log "Building porttorch -> $BIN_PATH"
go build -o "$BIN_PATH" ./cmd/scanner
chmod 755 "$BIN_PATH"

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
