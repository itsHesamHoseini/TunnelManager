package nodeops

import (
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"testing"
)

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
