// What a Windows build number means, and whether it is still supported.
//
// The scanner reports only the build - "10.0.17763" - because that is the
// fact it observed, read out of an NTLM message. Everything here is
// interpretation, and interpretation ages: new releases appear and
// support dates pass. Keeping it on this side means a new name or a
// lapsed date reaches every existing host on the next deploy, rather than
// only the hosts scanned after a scanner rollout.
//
// A build number does not say whether a machine is client or server -
// 10.0.17763 is Windows 10 1809 *and* Windows Server 2019, and the NTLM
// message cannot tell them apart. Both names are therefore carried, and a
// build is only called out of support once every edition sharing it has
// ended. That is why 17763 is not flagged even though the client half
// ended years ago: Server 2019 is supported into 2029, and calling that
// host out of support would be a claim the data does not carry.

export interface WindowsBuild {
  // Editions sharing this build, as Microsoft names them.
  names: string[];
  // When support ended for each name above, index for index. Undefined
  // where it has not ended or is not confidently known - an absent date
  // is "not stated", never "supported forever".
  supportEnded: Array<string | undefined>;
}

// Deliberately not exhaustive. An unknown build shows its number, which
// is still the precise answer the scan found; a guessed name would be
// worse than no name.
export const WINDOWS_BUILDS: Record<string, WindowsBuild> = {
  "10.0.26100": { names: ["Windows 11 24H2", "Windows Server 2025"], supportEnded: [undefined, undefined] },
  "10.0.22631": { names: ["Windows 11 23H2"], supportEnded: [undefined] },
  "10.0.22621": { names: ["Windows 11 22H2"], supportEnded: ["2025-10-14"] },
  "10.0.22000": { names: ["Windows 11 21H2"], supportEnded: ["2024-10-08"] },
  "10.0.20348": { names: ["Windows Server 2022"], supportEnded: [undefined] },
  "10.0.19045": { names: ["Windows 10 22H2"], supportEnded: ["2025-10-14"] },
  "10.0.19044": { names: ["Windows 10 21H2"], supportEnded: ["2024-06-11"] },
  "10.0.19043": { names: ["Windows 10 21H1"], supportEnded: ["2022-12-13"] },
  "10.0.19042": { names: ["Windows 10 20H2"], supportEnded: ["2023-05-09"] },
  "10.0.19041": { names: ["Windows 10 2004"], supportEnded: ["2021-12-14"] },
  "10.0.18363": { names: ["Windows 10 1909"], supportEnded: ["2022-05-10"] },
  "10.0.18362": { names: ["Windows 10 1903"], supportEnded: ["2020-12-08"] },
  // Shared build: the client half ended long ago, the server half has
  // not, so this is not flagged - see the note above.
  "10.0.17763": { names: ["Windows 10 1809", "Windows Server 2019"], supportEnded: ["2020-11-10", undefined] },
  "10.0.17134": { names: ["Windows 10 1803"], supportEnded: ["2021-05-11"] },
  "10.0.16299": { names: ["Windows 10 1709"], supportEnded: ["2020-10-13"] },
  "10.0.15063": { names: ["Windows 10 1703"], supportEnded: ["2019-10-08"] },
  "10.0.14393": { names: ["Windows 10 1607", "Windows Server 2016"], supportEnded: ["2019-04-09", undefined] },
  "10.0.10586": { names: ["Windows 10 1511"], supportEnded: ["2017-10-10"] },
  "10.0.10240": { names: ["Windows 10 1507"], supportEnded: ["2017-05-09"] },
  "6.3.9600": { names: ["Windows 8.1", "Windows Server 2012 R2"], supportEnded: ["2023-01-10", "2023-10-10"] },
  "6.2.9200": { names: ["Windows 8", "Windows Server 2012"], supportEnded: ["2016-01-12", "2023-10-10"] },
  "6.1.7601": { names: ["Windows 7 SP1", "Windows Server 2008 R2 SP1"], supportEnded: ["2020-01-14", "2020-01-14"] },
  "6.1.7600": { names: ["Windows 7", "Windows Server 2008 R2"], supportEnded: ["2013-04-09", "2013-04-09"] },
  "6.0.6002": { names: ["Windows Vista SP2", "Windows Server 2008 SP2"], supportEnded: ["2017-04-11", "2020-01-14"] },
  "5.2.3790": { names: ["Windows Server 2003", "Windows XP x64"], supportEnded: ["2015-07-14", "2015-07-14"] },
  "5.1.2600": { names: ["Windows XP"], supportEnded: ["2014-04-08"] },
};

export interface WindowsVersionInfo {
  build: string;
  // The release name(s), or null when the build is not in the table -
  // then the build number itself is all there is to show.
  label: string | null;
  // True only when every edition sharing this build has ended support.
  outOfSupport: boolean;
  // Why, in one sentence, for the tooltip.
  detail: string;
}

export function describeWindowsBuild(build: string | null, now = new Date()): WindowsVersionInfo | null {
  if (!build) return null;
  const entry = WINDOWS_BUILDS[build];
  if (!entry) {
    return {
      build,
      label: null,
      outOfSupport: false,
      detail: `Build ${build}. This build is not in the table, so only the number is known.`,
    };
  }

  const ended = entry.names.map((_, i) => {
    const date = entry.supportEnded[i];
    return date !== undefined && new Date(date).getTime() <= now.getTime();
  });
  const outOfSupport = ended.every(Boolean);

  const parts = entry.names.map((name, i) =>
    ended[i] ? `${name} (support ended ${entry.supportEnded[i]})` : name
  );
  let detail = `Build ${build}: ${parts.join(" or ")}.`;
  if (entry.names.length > 1 && !outOfSupport && ended.some(Boolean)) {
    // The shared-build case, spelled out rather than resolved: the build
    // alone cannot say which half this machine is.
    detail +=
      " A build number does not say whether a machine is the client or the server edition, so this is not flagged as out of support.";
  }
  return { build, label: entry.names.join(" / "), outOfSupport, detail };
}
