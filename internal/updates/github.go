package updates

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// gitHubClient is the in-package HTTP client. Modest timeout so the TUI never
// hangs on a stalled call; long downloads use the tools-package downloader
// which has its own 10-minute budget.
var gitHubClient = &http.Client{Timeout: 30 * time.Second}

// LatestCommit returns the most recent commit timestamp on the given branch
// for an owner/repo on GitHub. The caller uses this to compare against the
// .vanguard_updated marker for repo_archive rule sets.
//
// Surfaces rate-limit errors with the X-RateLimit-Reset epoch so the TUI can
// tell the user when to retry.
func LatestCommit(repo, branch string) (time.Time, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/commits/%s", repo, branch)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "VanGuard-DFIR-Toolkit")

	resp, err := gitHubClient.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("requesting %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return time.Time{}, rateLimitError(resp)
	}
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("github returned %d", resp.StatusCode)
	}

	var body struct {
		Commit struct {
			Committer struct {
				Date time.Time `json:"date"`
			} `json:"committer"`
		} `json:"commit"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return time.Time{}, fmt.Errorf("decoding response: %w", err)
	}
	return body.Commit.Committer.Date, nil
}

// LatestRelease returns the (tag, body, err) tuple for the most recent
// published release of owner/repo. Used by the VanGuard self-version check.
func LatestRelease(repo string) (tag, body string, err error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "VanGuard-DFIR-Toolkit")

	resp, err := gitHubClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("requesting %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return "", "", rateLimitError(resp)
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", "", fmt.Errorf("no published releases found for %s", repo)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("github returned %d", resp.StatusCode)
	}
	var rel struct {
		Tag  string `json:"tag_name"`
		Body string `json:"body"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", "", fmt.Errorf("decoding response: %w", err)
	}
	return rel.Tag, rel.Body, nil
}

// rateLimitError formats a useful error from a 403 response, including the
// reset time when the X-RateLimit-Reset header is present.
func rateLimitError(resp *http.Response) error {
	if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
		if epoch, err := strconv.ParseInt(reset, 10, 64); err == nil {
			when := time.Unix(epoch, 0).Local()
			return fmt.Errorf("github rate-limited; resets at %s (in %s)",
				when.Format("15:04:05"), time.Until(when).Truncate(time.Second))
		}
	}
	return fmt.Errorf("github rate-limited (403)")
}
