package broker

import (
	"reflect"
	"testing"
)

func testEngine() *Engine {
	return &Engine{cfg: &Config{Hosts: map[string]HostConfig{
		"target":  {Addr: "t:22", Jump: "mid"},
		"mid":     {Addr: "m:22", Jump: "bastion"},
		"bastion": {Addr: "b:22"},
		"direct":  {Addr: "d:22"},
		"loopA":   {Addr: "a:22", Jump: "loopB"},
		"loopB":   {Addr: "b:22", Jump: "loopA"},
		"badjump": {Addr: "x:22", Jump: "nope"},
	}}}
}

func TestResolveChain(t *testing.T) {
	e := testEngine()
	cases := []struct {
		host string
		want []string
	}{
		{"direct", []string{"direct"}},
		{"target", []string{"bastion", "mid", "target"}}, // orden de marcado
	}
	for _, c := range cases {
		got, err := e.resolveChain(c.host)
		if err != nil {
			t.Fatalf("%s: error inesperado: %v", c.host, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: cadena = %v, quiero %v", c.host, got, c.want)
		}
	}
}

func TestResolveChainErrors(t *testing.T) {
	e := testEngine()
	if _, err := e.resolveChain("loopA"); err == nil {
		t.Error("esperaba error por ciclo de bastión")
	}
	if _, err := e.resolveChain("badjump"); err == nil {
		t.Error("esperaba error por bastión desconocido")
	}
	if _, err := e.resolveChain("inexistente"); err == nil {
		t.Error("esperaba error por host desconocido")
	}
}
