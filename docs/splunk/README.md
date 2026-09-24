# Rebuilding Scan Stats in Splunk

Every chart on PortTorch's **Scan Stats** page, as an SPL search against
the HEC streams. CVE, EPSS and KEV are deliberately absent - those are not
rows anywhere in PortTorch, they are joined from `cve_cache` at query time,
so there is no stream to forward.

The field names here were captured off the wire from the real forwarder,
not written from the source. The searches themselves have **not** been run
against a Splunk instance - treat them as a starting point that needs one
pass in your own environment.

## Before anything

Enable the streams under **Settings → SIEM Forwarding**. The searches
below need **Scan results** (`porttorch:observation`), **Hosts**
(`porttorch:host`) and **TLS certificates** (`porttorch:certificate`);
the web-finding chart needs **Web findings** (`porttorch:finding`).

Three things that will otherwise cost you an afternoon:

- **Filter on `source`, never `sourcetype`.** A custom sourcetype set in
  PortTorch applies to all six streams; `source` stays distinct.
- **`_time` is when the scan saw it**, not when it was forwarded. Time
  pickers therefore select scans, which is what you want.
- **Pick a window at least as long as your slowest rescan cycle.** Last 30
  days is safe for a nightly schedule. Shorter, and ports that were not
  re-observed inside the window disappear from the "current state"
  searches below.

Replace `index=porttorch` throughout with whatever index the token writes
to.

## The one rule that makes or breaks a search

`porttorch:observation` is **history** - append-only, one event per port
per scan. Scan Stats shows **current state** - the newest observation per
host, port and protocol. A plain `stats count by port` over the raw stream
counts every observation ever made, which on a nightly schedule is the
same fleet multiplied by however many days you selected.

Reduce first. Save this as a macro called `porttorch_current_ports`:

```
index=porttorch source="porttorch:observation"
| stats latest(state) as state,
        latest(ip) as ip,
        latest(hostname) as hostname,
        latest(service_name) as service_name,
        latest(service_product) as service_product,
        latest(service_version) as service_version,
        latest(scanner_agent_name) as scanner
        by host_id, port, protocol
| search state=open
```

`latest()` sorts by `_time`, which is exactly the `DISTINCT ON (host_id,
port, protocol) ORDER BY observed_at DESC` behind the `current_host_ports`
view the page reads - and cheaper than `sort` + `dedup`.

The host stream needs the same treatment, since a host is re-sent every
time a scan refreshes it. Save as `porttorch_current_hosts`:

```
index=porttorch source="porttorch:host"
| stats latest(ip) as ip, latest(hostname) as hostname,
        latest(os_family) as os_family, latest(os_name) as os_name,
        latest(device_type) as device_type, latest(mac_vendor) as mac_vendor,
        latest(tags) as tags, latest(retired) as retired,
        latest(scanner_agent_name) as scanner
        by host_id
```

Scan Stats includes retired hosts by default with an opt-in toggle. To
match the toggle, append `| where retired="false"`.

## Totals

```
`porttorch_current_ports`
| stats dc(host_id) as hosts_with_open_ports, count as open_ports,
        dc(port) as distinct_ports, dc(service_name) as distinct_services
```

The page's **Hosts** total counts *every* host, including ones with no
open port at all - so take it from the host stream rather than the one
above:

```
`porttorch_current_hosts` | stats dc(host_id) as hosts
```

## Ports, services, protocols

These three count **open port entries**, the same unit the page uses.

```
` Top ports `
`porttorch_current_ports` | eval p=port."/".protocol | stats count by p | sort -count | head 10

` Services - a port nmap could not fingerprint is its own slice, not dropped `
`porttorch_current_ports`
| eval service=if(isnull(service_name) OR service_name="","unknown",service_name)
| stats count by service | sort -count | head 10

` Protocols `
`porttorch_current_ports` | eval protocol=upper(protocol) | stats count by protocol
```

### Port types

The page groups ports into nine functional categories from a hand-kept
table. `porttorch_port_categories.csv` in this directory is that table,
generated from `server/src/scanStats/portCategories.ts` and verified row
by row against the real `categorisePort()`. Upload it as a lookup named
`porttorch_port_categories` with `port` and `protocol` as the match
fields, then:

```
`porttorch_current_ports`
| lookup porttorch_port_categories port protocol OUTPUT category
| eval category=if(isnull(category),"Other",category)
| stats count by category | sort -count
```

Protocol is part of the key on purpose: 514/tcp is rsh while 514/udp is
syslog, and 69/udp is TFTP while 69/tcp is nothing in particular.

## Inventory

All four of these come from the host stream, and none of them exist in
the observation stream - that is what the host stream was added for.

```
` OS families - unclassified is its own slice, as on the page `
`porttorch_current_hosts`
| eval os_family=if(isnull(os_family) OR os_family="","Not classified",os_family)
| stats dc(host_id) as hosts by os_family | sort -hosts

` Device types `
`porttorch_current_hosts`
| eval device_type=if(isnull(device_type) OR device_type="","Not classified",device_type)
| stats dc(host_id) as hosts by device_type | sort -hosts

` Manufacturers. Mostly "Not resolved": nmap only resolves a MAC by ARP,
  so it is populated for hosts on a scanner's own segment and nothing else `
`porttorch_current_hosts`
| eval mac_vendor=if(isnull(mac_vendor) OR mac_vendor="","Not resolved",mac_vendor)
| stats dc(host_id) as hosts by mac_vendor | sort -hosts | head 10

` Tags. A host carries as many as apply, so this does not partition the fleet `
`porttorch_current_hosts` | mvexpand tags | stats dc(host_id) as hosts by tags | sort -hosts | head 10
```

## Software

Counted **per distinct host**, not per open port: the same product on
three ports of one machine is one thing to patch.

```
` Products `
`porttorch_current_ports` | where isnotnull(service_product) AND service_product!=""
| stats dc(host_id) as hosts by service_product | sort -hosts | head 10

` Products with version - an unidentified version keeps its own slice `
`porttorch_current_ports` | where isnotnull(service_product) AND service_product!=""
| eval software=service_product." ".if(isnull(service_version) OR service_version="","(version unknown)",service_version)
| stats dc(host_id) as hosts by software | sort -hosts | head 10
```

## Per scanner, top hosts, top subnets

```
`porttorch_current_ports` | stats dc(host_id) as hosts, count as open_ports by scanner

`porttorch_current_ports` | stats count as open_ports by ip | sort -open_ports | head 10

` /24s, ordered by exposure then host count, as the page orders them `
`porttorch_current_ports`
| rex field=ip "^(?<subnet>\d+\.\d+\.\d+)\."
| stats dc(host_id) as hosts, count as open_ports by subnet
| eval subnet=subnet.".0/24" | sort -open_ports -hosts | head 10
```

## Unconfirmed ports

A port still recorded open that the host's own most recent scan did not
re-confirm. Compared against **that host's newest observation**, not
against `now()` - a host nobody has scanned this week is not unconfirmed,
it is unscanned.

```
index=porttorch source="porttorch:observation"
| stats latest(state) as state, latest(_time) as seen by host_id, port, protocol
| eventstats max(seen) as host_newest by host_id
| where state="open" AND seen < host_newest
| stats count as unconfirmed_ports, dc(host_id) as hosts_affected
```

## Certificates

Reduce to the newest capture per host and port first - the stream is the
history of what each port presented.

Save as `porttorch_current_certs`:

```
index=porttorch source="porttorch:certificate"
| stats latest(not_after) as not_after, latest(not_before) as not_before,
        latest(self_signed) as self_signed, latest(issuer_cn) as issuer_cn,
        latest(subject_cn) as subject_cn, latest(tls_version) as tls_version,
        latest(key_algorithm) as key_algorithm, latest(key_bits) as key_bits,
        latest(ip) as ip
        by host_id, port
```

```
` Total, and how many are self-signed `
`porttorch_current_certs` | stats count as certificates, count(eval(self_signed="true")) as self_signed

` Issuance `
`porttorch_current_certs`
| eval issuance=if(self_signed="true","Self-signed","CA-issued") | stats count by issuance

` Expiry, with the page's own buckets `
`porttorch_current_certs`
| eval days=round((strptime(not_after,"%Y-%m-%dT%H:%M:%S.%3NZ")-now())/86400,0)
| eval bucket=case(isnull(not_after),"Unknown", days<0,"Expired", days<=30,"<= 30 days",
                   days<=90,"31-90 days", 1=1,"> 90 days")
| stats count by bucket

` TLS versions and key types `
`porttorch_current_certs` | eval tls_version=if(isnull(tls_version) OR tls_version="","unknown",tls_version)
| stats count by tls_version | sort -count
`porttorch_current_certs` | eval key=if(isnull(key_algorithm),"unknown",key_algorithm." ".key_bits)
| stats count by key | sort -count

` Issuers, every self-signed certificate collapsed into one slice -
  otherwise that chart is one slice per host and says nothing `
`porttorch_current_certs`
| eval issuer=if(self_signed="true","Self-signed",if(isnull(issuer_cn) OR issuer_cn="","unknown",issuer_cn))
| stats count by issuer | sort -count | head 10

` Weak keys: RSA under 2048. EC is deliberately excluded - EC 256 is
  roughly RSA 3072, so a bit-count threshold alone gets it backwards `
`porttorch_current_certs`
| where like(upper(key_algorithm),"%RSA%") AND key_bits<2048 | stats count as weak_keys
```

## Web findings

```
index=porttorch source="porttorch:finding"
| stats latest(severity) as severity by host_id, template_id, matched_at
| stats count by severity

` Most frequent templates `
index=porttorch source="porttorch:finding"
| stats dc(host_id) as hosts by template_id, severity | sort -hosts | head 10
```

## The join the host stream exists for

Anything on the page that crosses a port fact with a host fact - and
anything Scan Stats cannot do at all, since its charts are one dimension
each:

```
` Open ports by OS family `
`porttorch_current_ports`
| join type=left host_id [ `porttorch_current_hosts` | fields host_id, os_family ]
| eval os_family=if(isnull(os_family) OR os_family="","Not classified",os_family)
| stats count as open_ports, dc(host_id) as hosts by os_family | sort -open_ports

` Expired certificates on hosts tagged WebServer `
`porttorch_current_certs`
| join type=left host_id [ `porttorch_current_hosts` | fields host_id, tags, hostname ]
| where strptime(not_after,"%Y-%m-%dT%H:%M:%S.%3NZ") < now() AND mvfind(tags,"WebServer")>=0
| table hostname, ip, port, subject_cn, not_after
```

## Not in the feed

These Scan Stats cards have no stream behind them yet, so they cannot be
rebuilt here:

- **SSH host keys** (`ssh_host_keys`) - key types, weak keys, shared
  fingerprints.
- **Screenshot coverage** - `screenshots` is not forwarded.
- **Network coverage** - `monitored_networks` and the coverage derivation
  are computed on read, not stored.
- **Scan performance** - durations live on `scan_jobs`, which is not
  forwarded; only the scanners' own log lines are.
- **CVE / EPSS / KEV** - not rows anywhere, joined from `cve_cache` at
  query time.

## Regenerating the lookup

```
# from server/src/scanStats/portCategories.ts
python3 - <<'PY' > docs/splunk/porttorch_port_categories.csv
import re, csv, sys, pathlib
src = pathlib.Path('server/src/scanStats/portCategories.ts').read_text()
def m(name):
    body = re.search(rf"const {name}: Record<number, PortCategory> = \{{(.*?)\n\}};", src, re.S).group(1)
    return {int(p): c for p, c in re.findall(r'(\d+)\s*:\s*"([^"]+)"', re.sub(r"//.*", "", body))}
by_port, tcp_only, udp_only = m("BY_PORT"), m("TCP_ONLY"), m("UDP_ONLY")
ports = sorted(set(by_port) | set(tcp_only) | set(udp_only))
rows = [(p, proto, ov.get(p) or by_port.get(p) or "Other")
        for proto, ov in (("tcp", tcp_only), ("udp", udp_only)) for p in ports]
w = csv.writer(sys.stdout, lineterminator="\n")   # not \r\n - a stray CR rides into the lookup value
w.writerow(["port", "protocol", "category"])
for r in sorted(rows, key=lambda r: (r[0], r[1])): w.writerow(r)
PY
```
