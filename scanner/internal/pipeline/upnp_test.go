package pipeline

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestUpnpPortFromNmapRun(t *testing.T) {
	const rawXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.12" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="1900">
        <state state="open"/>
        <service name="upnp"/>
        <script id="upnp-info" output="Server: Linux/3.10 UPnP/1.0 MiniUPnPd/2.1"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	var run nmapRun
	if err := xml.Unmarshal([]byte(rawXML), &run); err != nil {
		t.Fatalf("unmarshaling test XML: %v", err)
	}

	port := upnpPortFromNmapRun(&run)
	if port == nil {
		t.Fatal("expected a non-nil PortResult")
	}
	if port.Port != 1900 || port.Protocol != "udp" || port.State != "open" || port.ServiceName != "upnp" {
		t.Errorf("unexpected port fields: %+v", port)
	}
	if len(port.ExtraScripts) != 1 || port.ExtraScripts[0].ID != "upnp-info" {
		t.Fatalf("expected exactly one upnp-info extra script, got %+v", port.ExtraScripts)
	}
	if want := "MiniUPnPd"; !strings.Contains(port.ExtraScripts[0].Output, want) {
		t.Errorf("expected output to contain %q, got %q", want, port.ExtraScripts[0].Output)
	}
}

func TestUpnpPortFromNmapRunNoResponse(t *testing.T) {
	// The common case: nothing answered on UDP/1900 at all, so nmap never
	// even opened a <port> element for it - must return nil, not a
	// fabricated result.
	const rawXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.12" addrtype="ipv4"/>
    <ports>
    </ports>
  </host>
</nmaprun>`

	var run nmapRun
	if err := xml.Unmarshal([]byte(rawXML), &run); err != nil {
		t.Fatalf("unmarshaling test XML: %v", err)
	}

	if port := upnpPortFromNmapRun(&run); port != nil {
		t.Errorf("expected nil when nothing answered, got %+v", port)
	}
}

func TestUpnpPortFromNmapRunNoHosts(t *testing.T) {
	if port := upnpPortFromNmapRun(&nmapRun{}); port != nil {
		t.Errorf("expected nil for an empty nmapRun, got %+v", port)
	}
}
