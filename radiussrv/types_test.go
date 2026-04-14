package radiussrv

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseClientsConf(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clients.conf")
	content := `
client nas1 {
	secret = s3cret
	shortname = nas-one
	ipaddr = 192.0.2.10
}
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	clients, err := ParseClientsConf(path)
	if err != nil {
		t.Fatalf("ParseClientsConf: %v", err)
	}
	c, ok := clients["192.0.2.10"]
	if !ok {
		t.Fatalf("expected key 192.0.2.10, got keys %#v", clients)
	}
	if c.Secret != "s3cret" {
		t.Fatalf("secret: got %q", c.Secret)
	}
	if c.ShortName != "nas-one" {
		t.Fatalf("shortname: got %q", c.ShortName)
	}
	if c.IPAddr != "192.0.2.10" {
		t.Fatalf("ipaddr: got %q", c.IPAddr)
	}
}

func TestParseClientsConf_UsesClientNameWhenNoIP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clients.conf")
	if err := os.WriteFile(path, []byte(`
client legacy {
	secret = x
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	clients, err := ParseClientsConf(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := clients["legacy"]; !ok {
		t.Fatalf("expected key legacy, got %#v", clients)
	}
}

func TestParseClientsConf_MissingFile(t *testing.T) {
	_, err := ParseClientsConf(filepath.Join(t.TempDir(), "nope.conf"))
	if err == nil {
		t.Fatal("expected error")
	}
}
