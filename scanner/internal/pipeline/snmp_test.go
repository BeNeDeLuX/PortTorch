package pipeline

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestSnmpPortFromNmapRun(t *testing.T) {
	const rawXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.9" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="161">
        <state state="open"/>
        <service name="snmp"/>
        <script id="snmp-info" output="STATUS: OPEN&#10;sysDescr: Cisco IOS Software&#10;sysName: switch-core-01"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	var run nmapRun
	if err := xml.Unmarshal([]byte(rawXML), &run); err != nil {
		t.Fatalf("unmarshaling test XML: %v", err)
	}

	port := snmpPortFromNmapRun(&run)
	if port == nil {
		t.Fatal("expected a non-nil PortResult")
	}
	if port.Port != 161 || port.Protocol != "udp" || port.State != "open" || port.ServiceName != "snmp" {
		t.Errorf("unexpected port fields: %+v", port)
	}
	if len(port.ExtraScripts) != 1 || port.ExtraScripts[0].ID != "snmp-info" {
		t.Fatalf("expected exactly one snmp-info extra script, got %+v", port.ExtraScripts)
	}
	if want := "switch-core-01"; !strings.Contains(port.ExtraScripts[0].Output, want) {
		t.Errorf("expected output to contain %q, got %q", want, port.ExtraScripts[0].Output)
	}
}

func TestSnmpPortFromNmapRunNoResponse(t *testing.T) {
	// The common case: nothing answered on UDP/161 at all, so nmap reports
	// no snmp-info script output (or no port element for it) - must return
	// nil, not a fabricated "open" port for a service that was never
	// actually confirmed present.
	const rawXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.9" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="161">
        <state state="open|filtered"/>
        <service name="snmp"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	var run nmapRun
	if err := xml.Unmarshal([]byte(rawXML), &run); err != nil {
		t.Fatalf("unmarshaling test XML: %v", err)
	}

	if port := snmpPortFromNmapRun(&run); port != nil {
		t.Errorf("expected nil when snmp-info produced no output, got %+v", port)
	}
}

func TestSnmpPortFromNmapRunNoHosts(t *testing.T) {
	if port := snmpPortFromNmapRun(&nmapRun{}); port != nil {
		t.Errorf("expected nil for an empty nmapRun, got %+v", port)
	}
}

// TestSnmpPortFromNmapRunMultipleScripts covers the Tier 2 addition of
// snmp-sysdescr/snmp-interfaces/snmp-netstat alongside snmp-info -
// captured generically (like nmap.go's per-port default case), so all
// scripts that produced output land in ExtraScripts, and one that ran
// but found nothing (e.g. snmp-netstat against a device with no active
// connections to report) is dropped rather than stored empty.
func TestSnmpPortFromNmapRunMultipleScripts(t *testing.T) {
	const rawXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.9" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="161">
        <state state="open"/>
        <service name="snmp"/>
        <script id="snmp-info" output="STATUS: OPEN&#10;sysDescr: Cisco IOS Software"/>
        <script id="snmp-sysdescr" output="System description: Cisco IOS Software, C2960 Software"/>
        <script id="snmp-interfaces" output="GigabitEthernet0/1&#10;  IP address: 10.0.0.9&#10;  Type: ethernetCsmacd"/>
        <script id="snmp-netstat" output=""/>
      </port>
    </ports>
  </host>
</nmaprun>`

	var run nmapRun
	if err := xml.Unmarshal([]byte(rawXML), &run); err != nil {
		t.Fatalf("unmarshaling test XML: %v", err)
	}

	port := snmpPortFromNmapRun(&run)
	if port == nil {
		t.Fatal("expected a non-nil PortResult")
	}
	if len(port.ExtraScripts) != 3 {
		t.Fatalf("expected exactly 3 extra scripts (empty snmp-netstat dropped), got %+v", port.ExtraScripts)
	}
	byID := map[string]string{}
	for _, s := range port.ExtraScripts {
		byID[s.ID] = s.Output
	}
	for _, id := range []string{"snmp-info", "snmp-sysdescr", "snmp-interfaces"} {
		if _, ok := byID[id]; !ok {
			t.Errorf("expected %q in ExtraScripts, got %+v", id, port.ExtraScripts)
		}
	}
	if _, ok := byID["snmp-netstat"]; ok {
		t.Errorf("snmp-netstat produced empty output and must not be stored, got %+v", port.ExtraScripts)
	}
}
