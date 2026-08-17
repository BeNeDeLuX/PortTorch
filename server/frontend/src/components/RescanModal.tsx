import { useState } from "react";
import { NSEProfileSelection, NucleiProfileSelection } from "../api";
import { IconRefresh, IconX } from "./icons";
import Modal from "./Modal";
import ScanProfilePicker from "./ScanProfilePicker";
import NucleiProfilePicker from "./NucleiProfilePicker";

const LAST_PROFILE_KEY = "porttorch.rescan.lastProfile";
const LAST_NUCLEI_PROFILE_KEY = "porttorch.rescan.lastNucleiProfile";

function loadLastProfile(): NSEProfileSelection {
  try {
    const raw = localStorage.getItem(LAST_PROFILE_KEY);
    if (!raw) return { kind: "default" };
    const parsed = JSON.parse(raw);
    if (parsed && (parsed.kind === "default" || parsed.kind === "all_safe" || parsed.kind === "custom")) {
      return parsed as NSEProfileSelection;
    }
  } catch {
    // ignore malformed/foreign localStorage value, fall through to default
  }
  return { kind: "default" };
}

function loadLastNucleiProfile(): NucleiProfileSelection {
  try {
    const raw = localStorage.getItem(LAST_NUCLEI_PROFILE_KEY);
    if (!raw) return { kind: "off" };
    const parsed = JSON.parse(raw);
    if (parsed && (parsed.kind === "off" || parsed.kind === "safe" || parsed.kind === "custom")) {
      return parsed as NucleiProfileSelection;
    }
  } catch {
    // ignore malformed/foreign localStorage value, fall through to off
  }
  return { kind: "off" };
}

// Confirmation popup opened by every "Rescan" trigger (Dashboard single +
// bulk, Host Detail single) instead of firing immediately - a rescan's
// scope/intrusiveness can now vary a lot by profile, so this always shows
// rather than silently reusing the last pick, but pre-selects that last
// pick (remembered per-browser, same convention as
// Dashboard.tsx's own porttorch.dashboard.tablePrefs) so confirming is
// normally a single click on the already-highlighted option.
export default function RescanModal({
  hostCount,
  onConfirm,
  onClose,
}: {
  hostCount: number;
  onConfirm: (profile: NSEProfileSelection, nucleiProfile: NucleiProfileSelection) => void;
  onClose: () => void;
}) {
  const [profile, setProfile] = useState<NSEProfileSelection>(loadLastProfile);
  const [nucleiProfile, setNucleiProfile] = useState<NucleiProfileSelection>(loadLastNucleiProfile);

  function handleConfirm() {
    localStorage.setItem(LAST_PROFILE_KEY, JSON.stringify(profile));
    localStorage.setItem(LAST_NUCLEI_PROFILE_KEY, JSON.stringify(nucleiProfile));
    onConfirm(profile, nucleiProfile);
  }

  return (
    <Modal title="Rescan" onClose={onClose}>
      <p className="host-meta">
        {hostCount === 1 ? "Rescan this host" : `Rescan ${hostCount} selected hosts`} using which profiles?
      </p>
      <label>
        Scan profile
        <ScanProfilePicker value={profile} onChange={setProfile} />
      </label>
      <label>
        Nuclei profile
        <NucleiProfilePicker value={nucleiProfile} onChange={setNucleiProfile} />
      </label>
      <div className="inline-form" style={{ marginTop: "1rem" }}>
        <button type="button" className="btn-icon-label" onClick={handleConfirm}>
          <IconRefresh /> Rescan
        </button>
        <button type="button" className="link-button btn-icon-label" onClick={onClose}>
          <IconX /> Cancel
        </button>
      </div>
    </Modal>
  );
}
