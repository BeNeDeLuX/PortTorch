"""PortTorch integration for Cortex XSOAR.

Covers every operation PortTorch's external API (`/api/v1`) exposes, which
is also every operation an API token can reach at all: the dashboard's own
`/api/*` routes are session-authenticated and the ingest API is the
scanner's private scanner<->webserver protocol, so neither is addressable
with a token and neither is a stable contract (see
server/src/integrations/openapi.ts).

Written as one file and unified into PortTorch.yml by build_yml.py - the
same source-plus-unified-YAML split demisto-sdk uses. The YAML is what
gets uploaded through the XSOAR web UI (Settings -> Integrations -> BYOI);
this is what gets edited.
"""

import json

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F403

urllib3.disable_warnings()

DEFAULT_PAGE_SIZE = 50
# The API's own hard cap (listHostsSchema), repeated here so a bad value
# fails with an explanation instead of becoming a 400 the analyst has to
# decode.
MAX_PAGE_SIZE = 200
# Bounds `all_results`, so a fleet-wide fetch against a large deployment
# cannot turn one command into an unbounded request loop.
MAX_AUTO_PAGES = 100

TRIAGE_STATES = ("false_positive", "accepted_risk", "fixed")


class PortTorchClient(BaseClient):
    """Thin wrapper over BaseClient - one bearer token, one base URL."""

    def __init__(self, base_url: str, token: str, verify: bool, proxy: bool):
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )

    def call(self, method: str, url_suffix: str, params: dict = None, json_data: dict = None):
        """Returns the decoded body, or None for a 204.

        `resp_type="response"` rather than "json" because three of these
        endpoints answer 204 with no body at all, and JSON-parsing an
        empty body raises where it should simply mean "done".
        """
        res = self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            json_data=json_data,
            resp_type="response",
            ok_codes=(200, 201, 204),
            error_handler=_raise_porttorch_error,
        )
        if res.status_code == 204 or not res.content:
            return None
        try:
            return res.json()
        except ValueError:
            raise DemistoException(
                f"PortTorch returned a non-JSON body ({res.status_code}) for {method} {url_suffix}: {res.text[:300]}"
            )


def _error_detail(res) -> str:
    """PortTorch's error bodies are `{"error": ...}` - a string for a
    hand-written message, or zod's nested field-error object for a
    malformed request. Both are rendered, rather than one of them
    reaching the analyst as `[object Object]`."""
    try:
        body = res.json()
    except ValueError:
        return res.text[:300]
    detail = body.get("error") if isinstance(body, dict) else None
    if detail is None:
        return res.text[:300]
    if isinstance(detail, str):
        return detail
    return json.dumps(detail)


def _raise_porttorch_error(res):
    """Turns each status this API actually uses into a message that says
    what to do about it. A bare "Error in API call [409]" tells an analyst
    nothing about the one thing that resolves it (passing scanner_agent)."""
    status = res.status_code
    detail = _error_detail(res)

    if status == 401:
        raise DemistoException(
            "PortTorch rejected the API token (401). It may be wrong, revoked, or expired - check "
            f"Admin -> API Tokens in the dashboard. Server said: {detail}"
        )
    if status == 403:
        raise DemistoException(
            "This API token is read-only (403), so it cannot trigger or cancel scans, or clear triage. "
            f"Issue a read_write token under Admin -> API Tokens, or change this one's scope. Server said: {detail}"
        )
    if status == 404:
        raise DemistoException(f"PortTorch found nothing matching the request (404): {detail}")
    if status == 409:
        candidates = []
        try:
            candidates = res.json().get("candidates") or []
        except ValueError:
            pass
        listed = ", ".join(f"{c.get('ip')} (scanner: {c.get('scannerAgentName') or 'unknown'})" for c in candidates)
        raise DemistoException(
            "The same IP or hostname exists under more than one scanner agent, so PortTorch will not guess which "
            f"device was meant (409). Re-run with scanner_agent set to one of: {listed or 'see the dashboard'}."
        )
    if status == 429:
        retry_after = res.headers.get("Retry-After", "60")
        raise DemistoException(
            f"This token hit PortTorch's rate limit (429); retry in {retry_after}s. The limit is per token and set "
            f"by API_TOKEN_RATE_LIMIT_PER_MINUTE on the webserver. Server said: {detail}"
        )
    raise DemistoException(f"PortTorch returned {status}: {detail}")


def _host_identity_args(args: dict) -> dict:
    """Every route but the ad-hoc scan identifies a host by ip OR hostname,
    with scanner_agent needed only to break a tie. Checked here so the
    failure is a clear message rather than a 400 round trip."""
    ip = args.get("ip")
    hostname = args.get("hostname")
    if not ip and not hostname:
        raise DemistoException("Provide either the ip or the hostname argument to identify the host.")
    if ip and hostname:
        raise DemistoException("Provide either ip or hostname, not both - PortTorch looks a host up by one of them.")
    return assign_params(ip=ip, hostname=hostname, scannerAgent=args.get("scanner_agent"))


def _finding_identity_args(args: dict) -> dict:
    """A finding is either a CVE, or a nuclei template plus the URL it
    matched - the same either/or the API enforces server-side."""
    cve_id = args.get("cve_id")
    template_id = args.get("template_id")
    matched_at = args.get("matched_at")
    if cve_id and (template_id or matched_at):
        raise DemistoException("Provide either cve_id, or template_id together with matched_at - not both.")
    if cve_id:
        return {"cveId": cve_id}
    if template_id and matched_at:
        return {"templateId": template_id, "matchedAt": matched_at}
    if template_id or matched_at:
        raise DemistoException("A web finding needs both template_id and matched_at to identify it.")
    raise DemistoException("Provide cve_id, or template_id together with matched_at, to identify the finding.")


def _page_size(args: dict) -> int:
    page_size = arg_to_number(args.get("page_size")) or DEFAULT_PAGE_SIZE
    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        raise DemistoException(f"page_size must be between 1 and {MAX_PAGE_SIZE} (PortTorch's own cap).")
    return page_size


def _normalize_port(raw: dict) -> dict:
    cves = [
        assign_params(
            ID=cve.get("id"),
            CVSS=cve.get("cvssScore"),
            Severity=cve.get("cvssSeverity"),
            Description=cve.get("description"),
        )
        for cve in raw.get("vulnerabilities") or []
    ]
    return assign_params(
        Port=raw.get("port"),
        Protocol=raw.get("protocol"),
        Service=raw.get("service"),
        Product=raw.get("product"),
        Version=raw.get("version"),
        Banner=raw.get("banner"),
        CPEs=raw.get("cpes"),
        ObservedAt=raw.get("observedAt"),
        CVEs=cves,
    )


def _normalize_host(raw: dict) -> dict:
    """One context shape for both host-producing commands.

    The two endpoints genuinely differ: GET /hosts returns flat snake_case
    rows straight out of the query, GET /hosts/lookup returns a nested
    camelCase enrichment record. Writing both to PortTorch.Host unchanged
    would put two different shapes under one context path, so a playbook
    reading PortTorch.Host.IP would work after one command and not the
    other. Both are mapped here instead; raw_response keeps the API's own
    shape for anyone who needs it.
    """
    os_info = raw.get("os") or {}
    last_scan = raw.get("lastScan") or {}
    last_request = raw.get("lastScanRequest") or {}

    host = assign_params(
        ID=raw.get("id"),
        IP=raw.get("ip"),
        Hostname=raw.get("hostname"),
        OSName=raw.get("os_name") or os_info.get("name"),
        OSFamily=raw.get("os_family") or os_info.get("family"),
        OSVendor=os_info.get("vendor"),
        DeviceType=raw.get("device_type") or os_info.get("deviceType"),
        OSAccuracy=os_info.get("accuracy"),
        MACAddress=raw.get("mac_address"),
        ScannerAgent=raw.get("scanner_agent_name") or last_scan.get("scannerAgentName"),
        FirstSeen=raw.get("first_seen_at") or raw.get("firstSeenAt"),
        LastSeen=raw.get("last_seen_at") or raw.get("lastSeenAt"),
        Tags=raw.get("tags"),
        OpenPorts=[_normalize_port(p) for p in raw.get("openPorts") or []],
    )
    if last_scan:
        host["LastScan"] = assign_params(
            ObservedAt=last_scan.get("observedAt"), ScannerAgent=last_scan.get("scannerAgentName")
        )
    if last_request:
        host["LastScanRequest"] = assign_params(
            Status=last_request.get("status"),
            CreatedAt=last_request.get("created_at"),
            CompletedAt=last_request.get("completed_at"),
        )
    return host


def _normalize_scan_request(raw: dict) -> dict:
    return assign_params(
        ID=raw.get("scanRequestId"),
        Status=raw.get("status"),
        CreatedAt=raw.get("createdAt"),
        ScannerAgent=raw.get("scannerAgentName"),
        NSEProfile=raw.get("profile"),
        NucleiProfile=raw.get("nucleiProfile"),
    )


def test_module(client: PortTorchClient) -> str:
    """One real authenticated call, deliberately the cheapest read there
    is - a read-only token has to pass this, so nothing here may write."""
    client.call("GET", "/hosts", params={"pageSize": 1})
    return "ok"


def list_hosts_command(client: PortTorchClient, args: dict) -> List[CommandResults]:
    params = assign_params(
        q=args.get("query"),
        port=args.get("port"),
        service=args.get("service"),
        tag=args.get("tag"),
        osFamily=args.get("os_family"),
        deviceType=args.get("device_type"),
        scannerAgentId=args.get("scanner_agent_id"),
        hasStalePorts=args.get("has_stale_ports"),
        lastSeenAfter=args.get("last_seen_after"),
        lastSeenBefore=args.get("last_seen_before"),
    )
    page_size = _page_size(args)
    page = arg_to_number(args.get("page")) or 1
    fetch_all = argToBoolean(args.get("all_results", False))

    first = client.call("GET", "/hosts", params={**params, "page": page, "pageSize": page_size})
    total = int(first.get("total", 0))
    raw_items = list(first.get("items") or [])

    if fetch_all:
        pages_fetched = 1
        while len(raw_items) < total and pages_fetched < MAX_AUTO_PAGES:
            page += 1
            pages_fetched += 1
            nxt = client.call("GET", "/hosts", params={**params, "page": page, "pageSize": page_size})
            batch = nxt.get("items") or []
            if not batch:
                break
            raw_items.extend(batch)

    hosts = [_normalize_host(h) for h in raw_items]
    readable = tableToMarkdown(
        f"PortTorch hosts ({len(hosts)} of {total})",
        hosts,
        headers=["IP", "Hostname", "OSFamily", "DeviceType", "ScannerAgent", "LastSeen"],
        headerTransform=pascalToSpace,
        removeNull=False,
    )
    return [
        CommandResults(
            outputs_prefix="PortTorch.Host",
            outputs_key_field="ID",
            outputs=hosts,
            readable_output=readable,
            raw_response=raw_items,
        ),
        CommandResults(
            outputs_prefix="PortTorch.HostSearch",
            outputs={"Total": total, "Page": page, "PageSize": page_size, "Returned": len(hosts)},
            readable_output="",
        ),
    ]


def get_host_command(client: PortTorchClient, args: dict) -> CommandResults:
    raw = client.call("GET", "/hosts/lookup", params=_host_identity_args(args))
    host = _normalize_host(raw)

    readable = tableToMarkdown(
        f"PortTorch host {host.get('IP')}",
        {
            "IP": host.get("IP"),
            "Hostname": host.get("Hostname"),
            "OS": host.get("OSName"),
            "OS family": host.get("OSFamily"),
            "Device type": host.get("DeviceType"),
            "Tags": ", ".join(host.get("Tags") or []),
            "First seen": host.get("FirstSeen"),
            "Last seen": host.get("LastSeen"),
            "Last scanned by": host.get("ScannerAgent"),
        },
        removeNull=False,
    )

    ports = host.get("OpenPorts") or []
    if ports:
        readable += tableToMarkdown(
            "Open ports",
            [
                {
                    "Port": f"{p.get('Port')}/{p.get('Protocol')}",
                    "Service": p.get("Service"),
                    "Product": p.get("Product"),
                    "Version": p.get("Version"),
                    "CVEs": len(p.get("CVEs") or []),
                    "Last confirmed": p.get("ObservedAt"),
                }
                for p in ports
            ],
            removeNull=False,
        )
        vuln_rows = [
            {
                "Port": f"{p.get('Port')}/{p.get('Protocol')}",
                "CVE": cve.get("ID"),
                "CVSS": cve.get("CVSS"),
                "Severity": cve.get("Severity"),
                "Description": (cve.get("Description") or "")[:200],
            }
            for p in ports
            for cve in p.get("CVEs") or []
        ]
        if vuln_rows:
            readable += tableToMarkdown("Correlated CVEs", vuln_rows, removeNull=False)
    else:
        readable += "\nNo open ports recorded for this host.\n"

    return CommandResults(
        outputs_prefix="PortTorch.Host",
        outputs_key_field="IP",
        outputs=host,
        readable_output=readable,
        raw_response=raw,
    )


def rescan_host_command(client: PortTorchClient, args: dict) -> CommandResults:
    body = _host_identity_args(args)
    body.update(assign_params(profile=args.get("profile"), priority=args.get("priority")))
    raw = client.call("POST", "/hosts/rescan", json_data=body)
    request = _normalize_scan_request(raw)

    readable = tableToMarkdown(
        "PortTorch rescan queued",
        {
            "Scan request": request.get("ID"),
            "Status": request.get("Status"),
            "NSE profile": request.get("NSEProfile"),
            "Created": request.get("CreatedAt"),
        },
        removeNull=False,
    )
    readable += (
        "\nThe scanner picks this up on its next poll - the request is queued, not started. Its port spec is "
        "whatever this host currently has open.\n"
    )
    return CommandResults(
        outputs_prefix="PortTorch.ScanRequest",
        outputs_key_field="ID",
        outputs=request,
        readable_output=readable,
        raw_response=raw,
    )


def cancel_scan_command(client: PortTorchClient, args: dict) -> CommandResults:
    identity = _host_identity_args(args)
    client.call("POST", "/hosts/cancel-scan", json_data=identity)
    target = identity.get("ip") or identity.get("hostname")
    return CommandResults(
        readable_output=(
            f"Cancellation requested for the scan running against {target}. The scanner notices on its next check "
            "and aborts - this is a request, not an immediate kill, and it only covers scans started from "
            "PortTorch's own queue."
        )
    )


def start_adhoc_scan_command(client: PortTorchClient, args: dict) -> CommandResults:
    body = assign_params(
        scannerAgent=args.get("scanner_agent"),
        targetSpec=args.get("target_spec"),
        portSpec=args.get("port_spec"),
        profile=args.get("profile"),
        nucleiProfile=args.get("nuclei_profile"),
        masscanRate=arg_to_number(args.get("masscan_rate")),
        priority=args.get("priority"),
    )
    for required in ("scannerAgent", "targetSpec", "portSpec"):
        if not body.get(required):
            raise DemistoException("scanner_agent, target_spec and port_spec are all required for an ad-hoc scan.")

    raw = client.call("POST", "/scans/adhoc", json_data=body)
    request = _normalize_scan_request(raw)

    readable = tableToMarkdown(
        "PortTorch ad-hoc scan queued",
        {
            "Scan request": request.get("ID"),
            "Status": request.get("Status"),
            "Scanner": request.get("ScannerAgent"),
            "Target": args.get("target_spec"),
            "Ports": args.get("port_spec"),
            "NSE profile": request.get("NSEProfile"),
            "Nuclei profile": request.get("NucleiProfile"),
            "Created": request.get("CreatedAt"),
        },
        removeNull=False,
    )
    return CommandResults(
        outputs_prefix="PortTorch.ScanRequest",
        outputs_key_field="ID",
        outputs=request,
        readable_output=readable,
        raw_response=raw,
    )


def triage_finding_command(client: PortTorchClient, args: dict) -> CommandResults:
    state = args.get("state")
    if state not in TRIAGE_STATES:
        raise DemistoException(f"state must be one of: {', '.join(TRIAGE_STATES)}.")

    body = _host_identity_args(args)
    body.update(_finding_identity_args(args))
    body["state"] = state
    body.update(assign_params(note=args.get("note"), reviewAt=args.get("review_at")))

    raw = client.call("PUT", "/findings/triage", json_data=body)
    triage = assign_params(
        ID=raw.get("id"), State=raw.get("state"), Note=raw.get("note"), ReviewAt=raw.get("reviewAt")
    )
    readable = tableToMarkdown(
        "PortTorch finding triaged",
        {
            "Triage id": triage.get("ID"),
            "State": triage.get("State"),
            "Note": triage.get("Note"),
            "Review due": triage.get("ReviewAt") or "never (the decision does not expire)",
        },
        removeNull=False,
    )
    return CommandResults(
        outputs_prefix="PortTorch.Triage",
        outputs_key_field="ID",
        outputs=triage,
        readable_output=readable,
        raw_response=raw,
    )


def clear_triage_command(client: PortTorchClient, args: dict) -> CommandResults:
    body = _host_identity_args(args)
    body.update(_finding_identity_args(args))
    client.call("DELETE", "/findings/triage", json_data=body)
    return CommandResults(
        readable_output=(
            "Triage cleared - the finding is untriaged again and reappears wherever triaged findings are hidden."
        )
    )


def api_request_command(client: PortTorchClient, args: dict) -> CommandResults:
    """Escape hatch for an /api/v1 endpoint added after this integration
    was built, so a new one does not require a new upload to reach.

    Deliberately not a way into the dashboard's own /api/* routes: those
    need a session cookie, and an API token gets 401 there no matter what
    is put in this field.
    """
    method = (args.get("method") or "GET").upper()
    endpoint = args.get("endpoint") or ""
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint

    try:
        params = json.loads(args["query"]) if args.get("query") else None
        json_data = json.loads(args["body"]) if args.get("body") else None
    except ValueError as exc:
        raise DemistoException(f"query and body must be valid JSON objects: {exc}")

    raw = client.call(method, endpoint, params=params, json_data=json_data)
    if raw is None:
        return CommandResults(readable_output=f"{method} /api/v1{endpoint} succeeded with no response body (204).")

    return CommandResults(
        outputs_prefix="PortTorch.RawResponse",
        outputs=raw,
        readable_output=tableToMarkdown(f"{method} /api/v1{endpoint}", raw),
        raw_response=raw,
    )


def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = urljoin((params.get("url") or "").rstrip("/"), "/api/v1")
    token = (params.get("credentials") or {}).get("password") or params.get("apikey")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"PortTorch: running command {command}")
    try:
        if not token:
            raise DemistoException(
                "No API token configured. Create one under Admin -> API Tokens in PortTorch - the plaintext value "
                "is shown once, at creation."
            )
        client = PortTorchClient(base_url=base_url, token=token, verify=verify, proxy=proxy)

        if command == "test-module":
            return_results(test_module(client))
        elif command == "porttorch-list-hosts":
            return_results(list_hosts_command(client, args))
        elif command == "porttorch-get-host":
            return_results(get_host_command(client, args))
        elif command == "porttorch-rescan-host":
            return_results(rescan_host_command(client, args))
        elif command == "porttorch-cancel-scan":
            return_results(cancel_scan_command(client, args))
        elif command == "porttorch-start-adhoc-scan":
            return_results(start_adhoc_scan_command(client, args))
        elif command == "porttorch-triage-finding":
            return_results(triage_finding_command(client, args))
        elif command == "porttorch-clear-triage":
            return_results(clear_triage_command(client, args))
        elif command == "porttorch-api-request":
            return_results(api_request_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented by the PortTorch integration.")
    except Exception as exc:
        return_error(f"Failed to execute {command}. Error: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
