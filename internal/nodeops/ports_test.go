package nodeops

import (
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"net"
	"testing"
)

func TestUnknownActualListenerStillBlocksPort(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	bind := engine.Binding{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, Protocol: "tcp"}
	if probeBinding(bind) == nil {
		t.Fatal("unknown real listener was ignored")
	}
	listener.Close()
	if e = probeBinding(bind); e != nil {
		t.Fatal("released port still reported occupied", e)
	}
}

func TestDockerNATReservationParsing(t *testing.T) {
	output := "0.0.0.0:24443->443/tcp, [::]:28100-28110->28100-28110/tcp\n127.0.0.1:5353->53/udp"
	for _, c := range []struct {
		host     string
		port     int
		protocol string
		want     bool
	}{{"127.0.0.2", 24443, "tcp", true}, {"::1", 28105, "tcp", true}, {"127.0.0.1", 5353, "udp", true}, {"127.0.0.2", 5353, "udp", false}, {"0.0.0.0", 5353, "tcp", false}} {
		if dockerConflict(output, engine.Binding{Host: c.host, Port: c.port, Protocol: c.protocol}) != c.want {
			t.Fatal("Docker published port was misclassified")
		}
	}
}
