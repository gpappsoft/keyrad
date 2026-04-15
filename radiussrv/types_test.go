/*
 * Copyright 2026 Marco Moenig <marco@sec73.io>, Oleg Ermoshkin <o@ermoshkin.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
