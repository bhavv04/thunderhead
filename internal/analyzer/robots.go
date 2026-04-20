package analyzer

import (
	"bufio"
	"log"
	"net/http"
	"strings"
)

func FetchDisallowedPaths(upstreamURL string) []string {
	resp, err := http.Get(upstreamURL + "/robots.txt")
	if err != nil {
		log.Printf("thunderhead: could not fetch robots.txt: %v", err)
		return []string{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("thunderhead: robots.txt returned %d, skipping", resp.StatusCode)
		return []string{}
	}

	var disallowed []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Disallow:") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "Disallow:"))
			if path != "" && path != "/" {
				disallowed = append(disallowed, path)
			}
		}
	}

	log.Printf("thunderhead: loaded %d disallowed paths from robots.txt", len(disallowed))
	return disallowed
}