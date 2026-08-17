#!/usr/bin/env bash
#
# PortTorch scanner installer - Debian/Ubuntu (apt-get) and RHEL/Rocky/
# Alma/Fedora (dnf) family distros.
#
# Two real, confirmed-by-testing gaps on the RHEL/Fedora side, not just
# reasoned about - see the "Known gaps on RHEL/Fedora" section in
# scanner/CLAUDE.md for the full detail:
#   - masscan is packaged on Fedora but NOT in RHEL9/Rocky9/Alma9's own
#     repos or EPEL (it was dropped from EPEL for EL9) - this script
#     builds it from source there instead, automatically.
#   - SELinux (Enforcing by default on RHEL/Fedora, unlike Debian) is a
#     second access-control layer on top of the setcap capabilities and
#     the self-update ACL grant below - this script does not write an
#     SELinux policy, only warns if it detects Enforcing mode.
# Chromium and FreeRDP screenshot support, by contrast, were confirmed
# working fine on both Fedora and RHEL-family via testing - no gap there.
# nuclei (web vulnerability scanning) is the inverse of masscan's gap:
# packaged via EPEL on RHEL-family, but NOT on Debian/Ubuntu or Fedora's
# own repos (also confirmed by testing) - built from source (go install)
# there instead.
#
# Installs masscan/nmap/gowitness/nuclei/xfreerdp(3)/Xvfb/ImageMagick/
# tesseract, gets the porttorch binary (downloaded prebuilt, or built from
# this checkout - see below), grants masscan/nmap raw socket capabilities,
# writes ~porttorch/.config/porttorch/config.yaml, and sets up a systemd
# service running "porttorch serve" so rescans and recurring schedules
# work without a human keeping a terminal open.
#
# Usage: sudo ./install.sh   (run from inside the scanner/ checkout)
#        sudo ./install.sh --rebuild-only   (after a "git pull" - just
#          rebuilds the porttorch binary from the current checkout and
#          restarts the service, skipping the package-install/gowitness/config steps.
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

# Detected unconditionally (not just in the full-install branch below) -
# grant_bin_dir_access further down needs pkg_install even on
# --rebuild-only, to fix up an existing install that predates the acl
# requirement.
DISTRO_FAMILY=""
DISTRO_PRETTY=""
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  DISTRO_PRETTY="${PRETTY_NAME:-}"
  case "${ID:-}:${ID_LIKE:-}" in
    *debian*) DISTRO_FAMILY="debian" ;;
    fedora:*|*:*fedora*|*:*rhel*) DISTRO_FAMILY="rhel" ;;
  esac
fi
if [[ -z "$DISTRO_FAMILY" ]]; then
  # /etc/os-release didn't match a known family (missing, or an
  # unrecognized ID/ID_LIKE) - fall back to whichever package manager is
  # actually present rather than refusing outright, same "best effort,
  # continue with a warning" spirit the old Debian-only check had.
  if command -v apt-get >/dev/null 2>&1; then
    DISTRO_FAMILY="debian"
  elif command -v dnf >/dev/null 2>&1; then
    DISTRO_FAMILY="rhel"
  fi
fi
pkg_install() {
  case "$DISTRO_FAMILY" in
    debian) apt-get install -y "$@" ;;
    rhel) dnf install -y "$@" ;;
    *) die "no supported package manager found (need apt-get for Debian/Ubuntu, or dnf for RHEL/Rocky/Alma/Fedora)" ;;
  esac
}

if $REBUILD_ONLY; then
  # These all need to already exist from a prior full install - rebuild-only
  # is deliberately just "recompile + restart", not a substitute for it.
  id "$SERVICE_USER" >/dev/null 2>&1 || die "system user '$SERVICE_USER' doesn't exist - run a full install first (without --rebuild-only)"
  [[ -f "$CONFIG_PATH" ]] || die "$CONFIG_PATH doesn't exist - run a full install first (without --rebuild-only)"
  [[ -f "$SYSTEMD_UNIT" ]] || die "$SYSTEMD_UNIT doesn't exist - run a full install first (without --rebuild-only)"
else
  if [[ -z "$DISTRO_FAMILY" ]]; then
    die "this installer supports Debian/Ubuntu (apt-get) and RHEL/Rocky/Alma/Fedora (dnf) - neither package manager was found"
  fi
  [[ -n "$DISTRO_PRETTY" ]] || DISTRO_PRETTY="an unrecognized distro (matched by package manager, not /etc/os-release)"
  log "Detected $DISTRO_PRETTY - using the $DISTRO_FAMILY package family"

  # --- required packages ------------------------------------------------
  # acl (setfacl/getfacl) is what lets the unprivileged $SERVICE_USER
  # write into $BIN_PATH's own directory for self-update - see the ACL
  # grant further below for why this can't just be a chown.
  # Whether nuclei ends up installed from the distro's own package below
  # (RHEL-family via EPEL only - see the check further down) - read by the
  # gowitness/nuclei build section further below to decide whether it
  # still needs a go install fallback.
  NUCLEI_FROM_PACKAGE=false
  if [[ "$DISTRO_FAMILY" == "debian" ]]; then
    log "Installing required packages (masscan, nmap, libcap2-bin, acl)"
    apt-get update -qq
    apt-get install -y masscan nmap libcap2-bin curl ca-certificates openssl acl
  else
    # EPEL doesn't exist on (and isn't needed by) Fedora itself - only
    # RHEL/Rocky/Alma/CentOS need it enabled, for acl and several of the
    # optional packages below.
    if [[ "${ID:-}" != "fedora" ]]; then
      log "Enabling EPEL (needed for several packages below on RHEL-family)"
      dnf install -y epel-release
    fi
    log "Installing required packages (nmap, libcap, acl)"
    dnf install -y nmap libcap ca-certificates openssl acl
    # curl-minimal (preinstalled on RHEL-family minimal images, including
    # this installer's own test containers) already provides a working
    # curl - installing the full "curl" package on top of it is a real,
    # confirmed-by-testing package conflict ("curl-minimal ... conflicts
    # with curl provided by curl ...") that dnf refuses without
    # --allowerasing. Simplest fix: only install it if curl isn't already
    # available under either name - curl-minimal's own curl is fully
    # sufficient for the plain HTTPS downloads (-fsSL) this script does.
    command -v curl >/dev/null 2>&1 || dnf install -y curl

    # masscan is packaged on Fedora but NOT in RHEL9/Rocky9/Alma9's own
    # repos or EPEL - confirmed by testing (dnf search finds nothing even
    # with EPEL and CRB both enabled), not assumed; EPEL carried it for
    # EL7/EL8 but it was dropped for EL9. Try the package first since
    # it's faster and gets distro-maintained updates; only build from
    # source when that genuinely isn't an option. Confirmed by testing
    # that this build actually works and runs on Rocky Linux 9.
    if dnf install -y masscan 2>/dev/null; then
      log "masscan installed from the distro's own package"
    else
      log "masscan isn't packaged for this distro - building it from source instead"
      # libpcap-devel lives in CRB (CodeReady Builder), not the base repo
      # or EPEL - a real, confirmed-by-testing gap: a stock Rocky/RHEL9
      # host with only EPEL enabled (as above) fails this dnf install
      # outright ("Unable to find a match: libpcap-devel") before ever
      # reaching the masscan build. Not needed on Fedora, which has no
      # CRB-equivalent split and already has this package directly.
      if [[ "${ID:-}" != "fedora" ]]; then
        dnf install -y dnf-plugins-core
        dnf config-manager --set-enabled crb
      fi
      dnf install -y gcc make git libpcap-devel
      tmp_masscan_src="$(mktemp -d)"
      git clone --depth 1 https://github.com/robertdavidgraham/masscan.git "$tmp_masscan_src/masscan"
      make -C "$tmp_masscan_src/masscan" -j"$(nproc)"
      install -m 755 "$tmp_masscan_src/masscan/bin/masscan" /usr/local/bin/masscan
      rm -rf "$tmp_masscan_src"
    fi

    # nuclei is the inverse situation from masscan above: unpackaged on
    # Debian/Ubuntu and Fedora's own repos (confirmed by testing - apt-
    # cache/dnf search find nothing for either), but genuinely available
    # via EPEL on RHEL-family - confirmed by testing (dnf search on Rocky
    # Linux 9 with EPEL enabled matches "nuclei.x86_64", version 3.11.0).
    # Only attempted here (not on Fedora, which has no EPEL) - the go
    # install fallback below covers Debian/Fedora/a failed EPEL attempt
    # alike.
    if [[ "${ID:-}" != "fedora" ]] && dnf install -y nuclei 2>/dev/null; then
      log "nuclei installed from the distro's own package (EPEL)"
      NUCLEI_FROM_PACKAGE=true
    fi
  fi

  # --- optional packages (screenshots/OCR are best-effort scanner features) --
  install_optional() {
    local pkg="$1"
    if pkg_install "$pkg"; then
      return 0
    fi
    warn "could not install '$pkg' - the feature that needs it will just be skipped (best-effort, see doctor output at the end)"
    return 0
  }
  # Package names differ by family, but every one of these was confirmed
  # by testing to actually install and work on both Fedora and RHEL-family
  # (Rocky Linux 9) - including Chromium and FreeRDP, which don't need
  # EPEL on Fedora but do need it enabled above on RHEL-family. FreeRDP's
  # CLI binary is named "xfreerdp" (not "xfreerdp3") on both, even where
  # the package itself ships FreeRDP 3.x (Fedora) rather than 2.x (Rocky)
  # - handled below when config.yaml is generated, not here.
  log "Installing optional packages (chromium, freerdp, Xvfb, ImageMagick, tesseract)"
  if [[ "$DISTRO_FAMILY" == "debian" ]]; then
    install_optional chromium
    install_optional freerdp3-x11
    install_optional xvfb
    install_optional imagemagick
    install_optional tesseract-ocr
  else
    install_optional chromium
    install_optional freerdp
    install_optional xorg-x11-server-Xvfb
    install_optional ImageMagick
    install_optional tesseract
  fi
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
    # where the required-packages pass above (which now includes acl)
    # never ran. A single small package here is cheap enough not to need
    # its own --rebuild-only opt-out.
    pkg_install acl || { warn "couldn't install 'acl' - self-update won't be able to write to $BIN_DIR ('sudo setfacl -m u:$SERVICE_USER:rwx $BIN_DIR' manually, or it'll keep failing)"; return 0; }
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

  # --- nuclei (web vulnerability scanning) - optional, best-effort --------
  if $NUCLEI_FROM_PACKAGE; then
    log "nuclei already installed from the distro's package (EPEL) above"
  else
    log "Building nuclei -> /usr/local/bin/nuclei"
    if ! GOBIN=/usr/local/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest; then
      warn "nuclei build failed - web vulnerability scanning will be skipped (best-effort, see doctor output at the end)"
    fi
  fi
  if command -v nuclei >/dev/null 2>&1; then
    log "Fetching nuclei templates (one-time - not kept up to date automatically, see CLAUDE.md)"
    nuclei -update-templates || warn "nuclei template update failed - web vulnerability scanning may find nothing until 'nuclei -update-templates' is run manually"
  fi

  # --- raw socket capabilities for masscan/nmap ---------------------------
  log "Granting cap_net_raw,cap_net_admin to masscan/nmap"
  setcap cap_net_raw,cap_net_admin+eip "$(command -v masscan)"
  setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)"

  # SELinux (Enforcing by default on RHEL/Fedora, unlike Debian) is a
  # second access-control layer on top of the capabilities above and the
  # ACL grant further below - a file capability or POSIX ACL permission
  # SELinux's own policy doesn't separately allow can still be silently
  # denied. This installer does not attempt to write an SELinux policy,
  # only warns here - not verified end-to-end against a real enforcing
  # policy, unlike everything else in this script's RHEL/Fedora support.
  # If masscan/nmap mysteriously can't raw-socket despite `getcap
  # $(command -v masscan)` showing the capability correctly, or
  # self-update can't write its own binary despite `getfacl "$BIN_DIR"`
  # showing the ACL correctly, check `ausearch -m avc -ts recent` (or
  # `journalctl -t setroubleshoot`) for a denial before assuming either
  # mechanism itself is broken.
  if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" == "Enforcing" ]]; then
    warn "SELinux is Enforcing on this host - if masscan/nmap or self-update misbehave despite the capabilities/ACL above being set correctly, check 'ausearch -m avc -ts recent' for a policy denial"
  fi

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

    # xfreerdpPath's compiled-in default ("xfreerdp3") only matches
    # Debian's freerdp3-x11 package - Fedora/RHEL-family's freerdp
    # package installs the binary as plain "xfreerdp" instead (confirmed
    # by testing on both Fedora 41 and Rocky Linux 9 - the CLI flags this
    # scanner uses are compatible with both the FreeRDP 3.x Fedora ships
    # and the FreeRDP 2.x Rocky ships, so only the binary name differs).
    # Only rewritten when "xfreerdp3" doesn't actually resolve but plain
    # "xfreerdp" does, so a Debian install's config.yaml looks exactly as
    # it always has.
    if ! command -v xfreerdp3 >/dev/null 2>&1 && command -v xfreerdp >/dev/null 2>&1; then
      sed -i "s|^xfreerdpPath:.*|xfreerdpPath: \"xfreerdp\"|" "$CONFIG_PATH"
    fi
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
echo "  add --rebuild-only to skip the package-install/gowitness/config/systemd steps and just do that."
if $BUILT_FROM_SOURCE; then
  echo "  This install was built from source. Checking out a 'scanner-vX.Y.Z' tag"
  echo "  next time downloads a prebuilt binary instead (add --from-source to opt out)."
else
  echo "  This install used the prebuilt binary from release $release_tag."
fi
