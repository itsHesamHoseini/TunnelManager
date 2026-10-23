package controller

import (
	"errors"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"reflect"
)

func carryMappingProbe(prior, next engine.Spec) (*engine.Probe, error) {
	probe := prior.Application
	if probe == nil || !reflect.DeepEqual(probe, next.Application) || probe.Endpoint.Host != prior.TransportRemote.Host {
		return next.Application, nil
	}
	for _, old := range prior.Routes {
		if old.User.Port != probe.Endpoint.Port {
			continue
		}
		for _, route := range next.Routes {
			if route.ID == old.ID {
				copy := *probe
				copy.Endpoint = engine.Endpoint{Host: next.TransportRemote.Host, Port: route.User.Port}
				return &copy, nil
			}
		}
		return nil, errors.New("removed_mapping_has_application_probe_review")
	}
	return next.Application, nil
}
