package doctor

import "testing"

func TestXDPAttachedOutput(t *testing.T) {
	cases := []struct {
		out  string
		want bool
	}{
		{"2: eth0: <BROADCAST,UP> mtu 1500 qdisc fq_codel state UP", false},
		{"2: xdp0: <BROADCAST,UP> mtu 1500 qdisc noqueue state UP", false},
		{"2: vxdp: <BROADCAST> mtu 1500", false},
		{"2: eth0: <BROADCAST> prog/xdp mtu 1500", false},
		{"2: eth0: <BROADCAST,UP> mtu 1500 xdp qdisc fq_codel state UP", true},
		{"2: eth0: <BROADCAST,UP> mtu 1500 xdp/id:9 qdisc fq_codel state UP", true},
		{"2: eth0: <BROADCAST,UP> mtu 1500 xdpgeneric/id:42 qdisc fq_codel state UP", true},
		{"2: eth0: <BROADCAST,UP> mtu 1500 xdpdrv/id:7 qdisc mq state UP", true},
		{"2: eth0: <BROADCAST,UP> mtu 1500 xdpoffload/id:3 qdisc mq state UP", true},
	}
	for _, c := range cases {
		if got := xdpAttachedOutput([]byte(c.out)); got != c.want {
			t.Errorf("%q: got %v want %v", c.out, got, c.want)
		}
	}
}

func TestXDPAttachmentSeverity(t *testing.T) {
	if got := xdpAttachmentResult("eth0", true, false, true, false); got.Status != StatusError {
		t.Fatalf("active, not bypass, not attached: %v", got.Status)
	}
	if got := xdpAttachmentResult("eth0", true, false, true, true); got.Status != StatusOK {
		t.Fatalf("bypass: %v", got.Status)
	}
	if got := xdpAttachmentResult("eth0", true, false, false, false); got.Status != StatusWarn {
		t.Fatalf("agent inactive: %v", got.Status)
	}
	if got := xdpAttachmentResult("eth0", false, false, true, false); got.Status != StatusWarn {
		t.Fatalf("probe failed: %v", got.Status)
	}
	if got := xdpAttachmentResult("eth0", true, true, true, false); got.Status != StatusOK {
		t.Fatalf("attached: %v", got.Status)
	}
}
