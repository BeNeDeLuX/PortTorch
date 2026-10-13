// Byte and bit-rate formatting for the scanner metrics views.

export function formatBytes(n: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 10 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

// Network throughput reads in bits per second, the unit links are sold and
// monitored in - "40 Mbit/s" is comparable to a 1 Gbit uplink at a glance.
export function formatBitRate(bytesPerSec: number): string {
  const units = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s"];
  let v = bytesPerSec * 8;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v >= 10 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}
