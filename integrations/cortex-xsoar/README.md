# PortTorch integration for Cortex XSOAR

A BYOI ("bring your own integration") package that lets XSOAR drive PortTorch:
look hosts up with their open ports, service fingerprints and correlated CVEs,
queue rescans and ad-hoc scans, stop a running scan, and record triage decisions
so a handled finding stops resurfacing.

`PortTorch.yml` is the file you upload. Everything else in this directory is the
source it is built from.

## What it covers

Every operation PortTorch's external API (`/api/v1`) exposes - which is also
every operation an API token can reach at all. The dashboard's own `/api/*`
routes are session-authenticated, and the ingest API is the private
scanner-to-webserver protocol; a token gets `401` on both, by design, and
neither is a stable contract. The authoritative spec for what this integration
speaks is the instance's own Swagger UI at `/api/v1/docs`.

| Command | Endpoint | Token scope |
| --- | --- | --- |
| `porttorch-list-hosts` | `GET /hosts` | read |
| `porttorch-get-host` | `GET /hosts/lookup` | read |
| `porttorch-rescan-host` | `POST /hosts/rescan` | read_write |
| `porttorch-cancel-scan` | `POST /hosts/cancel-scan` | read_write |
| `porttorch-start-adhoc-scan` | `POST /scans/adhoc` | read_write |
| `porttorch-triage-finding` | `PUT /findings/triage` | read (see below) |
| `porttorch-clear-triage` | `DELETE /findings/triage` | read_write |
| `porttorch-api-request` | anything under `/api/v1` | depends on the endpoint |

## Installing

1. **Create an API token in PortTorch.** Sign in as an admin, open
   **Admin → API Tokens**, create a token, and copy the plaintext value - it is
   shown once, at creation.
   - Pick **read_write** if XSOAR should be able to queue or cancel scans.
     **read** is enough for lookups and listing.
   - Optionally restrict the token to specific scanner agents. Every command
     then only ever sees those scanners' hosts, including
     `porttorch-get-host` - the restriction is applied at the lookup, not just
     on the listing.
   - Optionally set an expiry. It cannot be changed later; the scope can.
2. **Upload the integration.** In XSOAR, go to **Settings → Integrations →
   Instances**, click **BYOI** (older builds: *Import integration*), and upload
   `PortTorch.yml`.
3. **Add an instance.** Search for *PortTorch* in the integrations list, click
   **Add instance**, and fill in:
   - **PortTorch server URL** - the dashboard's base URL including the port,
     e.g. `https://porttorch.internal:8443`. Do not append `/api/v1`.
   - **API Token** - the value from step 1.
   - **Trust any certificate** - see TLS below.
   - **Use system proxy settings** - leave off unless XSOAR genuinely reaches
     PortTorch through a proxy. PortTorch is normally internal.
4. Click **Test**. It performs one real authenticated read (`GET /hosts` with
   `pageSize=1`), so a read-only token passes it too.

### TLS

PortTorch generates its own self-signed certificate on first boot. Preferably
upload a real certificate under **Settings → TLS Certificate** in PortTorch, or
add the issuing CA to the XSOAR engine's trust store. *Trust any certificate* is
the fallback while neither is in place.

### Docker image

The YAML ships `dockerimage: demisto/python3:latest`. If your deployment pins
images (air-gapped, or a curated registry), change that line to whichever
`demisto/python3` tag your XSOAR already has before uploading. The code needs
nothing beyond `requests`, which every `demisto/python3` image carries.

## Using it

### Enrich a host seen in an alert

```
!porttorch-get-host ip=10.14.2.37
```

Returns the host's open ports with service/version fingerprints, correlated CVEs
(with CVSS score and severity), tags, and when and by which scanner it was last
seen - all under `PortTorch.Host`.

### Find everything exposing a service

```
!porttorch-list-hosts port=3389 all_results=true
!porttorch-list-hosts tag=WebServer port=80,-443
!porttorch-list-hosts query=CVE-2019-11248
```

Filters are the dashboard's own: a leading minus on `port`, `service` or `tag`
excludes instead of includes, and `query` is the same free-text search that
matches IPs, hostnames, banners, service products, NSE script output, OCR'd
screenshot text and CVE ids.

### Confirm an exposure before escalating

```
!porttorch-rescan-host ip=10.14.2.37 priority=high
```

Queues a rescan of that host's currently open ports on whichever scanner last
scanned it. The request is **queued, not started** - the scanner picks it up on
its next poll, and the result lands in PortTorch, not back in this command's
output. A playbook that needs the result should wait and then call
`porttorch-get-host` again.

### Scan something PortTorch has never seen

```
!porttorch-start-adhoc-scan scanner_agent="dmz-scanner" target_spec=10.9.4.0/24 port_spec=80,443,U:53
```

`target_spec` takes an IPv4 address, CIDR, `start-end` range, a comma-separated
list of IPv6 addresses, or a DNS hostname - a hostname is resolved by the
scanner itself, on its own network, which is the point: the webserver has no
visibility into a scanner's DNS.

Mind the cost of a wide `port_spec`, especially with `U:` parts. An unanswered
UDP probe can only time out, never be refused, so a wide UDP range runs for
hours or days where the same TCP range takes minutes. `masscan_rate` lowers the
packet rate for one scan without touching the scanner's own configuration.

### Close the loop from a ticket

```
!porttorch-triage-finding ip=10.14.2.37 cve_id=CVE-2019-11248 state=accepted_risk note="Mitigated by ACL, ticket INC-4821" review_at=2027-01-31T00:00:00Z
```

`false_positive` and `fixed` drop the finding out of the host's risk indicator;
`accepted_risk` deliberately still counts there, because deciding to live with an
exposure does not make the host less exposed. All three silence EPSS and KEV
alerting for that finding. Without `review_at` the decision never expires, which
is rarely what an accepted risk should mean.

### Reach an endpoint this integration does not name

```
!porttorch-api-request endpoint=/hosts/lookup query=`{"ip": "10.14.2.37"}`
```

An escape hatch so an endpoint added to `/api/v1` after this integration was
built can be used without a new upload. It is not a way into the dashboard's own
`/api/*` routes.

## Things worth knowing

- **A host's identity is (IP, scanner agent).** Two scanners in two separate
  networks can each have a real device at the same private address, so PortTorch
  refuses to guess which was meant. Commands that hit that case fail with the
  candidate list; re-run with `scanner_agent` set.
- **Tokens are rate limited per token**, 120 requests/minute by default
  (`API_TOKEN_RATE_LIMIT_PER_MINUTE` on the webserver, `0` disables it). A
  throttled call fails with the retry delay named rather than silently. Keep
  `all_results` in mind on a large fleet - it pages at up to 200 hosts per
  request and stops after 100 pages.
- **`porttorch-triage-finding` currently works with a read-only token**, unlike
  every other writing command. That is PortTorch's own behaviour - `PUT
  /findings/triage` is not behind its write-scope guard while `DELETE` on the
  same path is - and is stated here because a read-only token is otherwise
  assumed to be unable to change anything. Confirmed by testing, not inferred.
- **Everything PortTorch stores and returns is UTC ISO 8601.** Timezone
  preferences in the dashboard are display-only and do not affect this API.
- **There is no `fetch-incidents`.** PortTorch pushes rather than being polled:
  configure a webhook channel under **Admin → Webhooks** pointing at an XSOAR
  endpoint, and subscribe to the events that should raise an incident
  (`host.new`, `port.opened`, `nuclei.finding`, `vulnerability.kev`,
  `scanner.offline`, ...), filtered by scanner, tag or minimum severity. A
  polling fetch built on `GET /hosts?lastSeenAfter=` is possible if a push
  channel is not an option - it just isn't built.
- **There is no reputation command** (`!ip`). PortTorch says what is running in
  your own network; it is not a reputation source, and giving its findings a
  DBotScore would misrepresent them.

## Developing

`PortTorch.py` (code) and `PortTorch.meta.yml` (metadata) are the sources;
`PortTorch.yml` is generated from both, because XSOAR's BYOI upload takes exactly
one file but a Python file living inside a YAML string cannot be compiled,
linted or diffed. This is the same split `demisto-sdk unify` performs, written
out here so the build needs nothing but a stock Python with PyYAML.

```
python3 build_yml.py     # regenerate PortTorch.yml from the two sources
python3 validate.py      # check the result before uploading it anywhere
```

`validate.py` checks what a broken BYOI upload actually fails on: YAML that will
not parse, embedded Python that will not compile, a stale `PortTorch.yml` whose
code no longer matches `PortTorch.py`, a command declared but never handled (or
handled but never declared), an argument the UI offers that the code never reads,
and required metadata fields.

Run both after editing either source. The generated file is committed, so
someone who only wants to install the integration never has to build anything.
