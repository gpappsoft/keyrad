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
	"bufio"
	"os"
	"regexp"
	"strings"
)

// ClientConfig holds shared secret and display metadata for one RADIUS client entry.
type ClientConfig struct {
	Secret    string
	ShortName string
	IPAddr    string
}

// RadiusAttribute describes one attribute to add to an Access-Accept when scopes match.
type RadiusAttribute struct {
	Vendor    uint32 `yaml:"vendor"`     // Vendor ID (0 = standard attribute)
	Attribute int    `yaml:"attribute"`  // Attribute type number
	Value     string `yaml:"value"`      // Attribute value
	ValueType string `yaml:"value_type"` // "string" (default), "integer", "ipaddr"
}

// ScopeRadiusMapping maps a scope name, group name, or regex pattern (prefix "re:") to RADIUS attributes.
type ScopeRadiusMapping map[string][]RadiusAttribute

// ParseClientsConf reads a FreeRADIUS-style clients.conf file and returns a map keyed by
// ipaddr when set, otherwise by the client block name.
func ParseClientsConf(path string) (map[string]ClientConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	clients := make(map[string]ClientConfig)
	var currentClient string
	var currentConfig ClientConfig
	inClient := false
	scanner := bufio.NewScanner(file)
	clientRe := regexp.MustCompile(`^client\s+([^\s{]+)\s*{`)
	secretRe := regexp.MustCompile(`^\s*secret\s*=\s*(\S+)`)
	shortnameRe := regexp.MustCompile(`^\s*shortname\s*=\s*(\S+)`)
	ipaddrRe := regexp.MustCompile(`^\s*ipaddr\s*=\s*(\S+)`)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !inClient {
			if m := clientRe.FindStringSubmatch(line); m != nil {
				currentClient = m[1]
				currentConfig = ClientConfig{}
				inClient = true
			}
			continue
		}
		if line == "}" {
			key := currentConfig.IPAddr
			if key == "" {
				key = currentClient
			}
			clients[key] = currentConfig
			inClient = false
			continue
		}
		if m := secretRe.FindStringSubmatch(line); m != nil {
			currentConfig.Secret = m[1]
		}
		if m := shortnameRe.FindStringSubmatch(line); m != nil {
			currentConfig.ShortName = m[1]
		}
		if m := ipaddrRe.FindStringSubmatch(line); m != nil {
			currentConfig.IPAddr = m[1]
		}
	}
	return clients, scanner.Err()
}
