package auth

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

type ClientConfig struct {
	Secret    string
	ShortName string
	IPAddr    string
}

type ScopeRadiusMapping map[string]struct {
	Attribute int    `yaml:"attribute"`
	Value     string `yaml:"value"`
}

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
