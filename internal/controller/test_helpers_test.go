package controller

import (
	"github.com/coder/websocket"
	"github.com/itsHesamHoseini/TunnelManager/internal/limit"
	"github.com/itsHesamHoseini/TunnelManager/internal/ui"
	"net/http"
)

func schemaFS() (string, error)                    { b, e := schema.ReadFile("schema.sql"); return string(b), e }
func newLimiter() *limit.Limiter                   { return limit.New() }
func emptyConnections() map[string]*websocket.Conn { return map[string]*websocket.Conn{} }

func testUI() http.Handler { return ui.Handler() }
