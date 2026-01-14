---
type: advisory
namespace: google
name: chrome
full_name: "Chrome Security Release"
operator: "secid:entity/google"

urls:
  website: "https://chromereleases.googleblog.com/search/label/Stable%20updates"
  release_notes: "https://chromereleases.googleblog.com/"

id_pattern: "CVE-\\d{4}-\\d{4,}"

examples:
  - "secid:advisory/google/chrome#CVE-2024-0519"
  - "secid:advisory/google/chrome#CVE-2023-7024"

status: active
---

# Chrome Security Release

Google Chrome security updates.

## Format

```
secid:advisory/google/chrome#CVE-YYYY-NNNN
```

## Resolution

Chrome CVEs are documented in release blog posts:

```
secid:advisory/google/chrome#CVE-2024-0519
  → Search chromereleases.googleblog.com
  → https://crbug.com/{bug_id} (if public)
```

## Notes

- Chrome releases frequently with security fixes
- Many CVEs per release (listed in "Stable channel update" posts)
- Chromium bugs often restricted until fix ships
- `crbug.com` redirects to Chromium bug tracker
- Chrome vulnerabilities often exploited in the wild
- Security fixes documented in "Stable updates" labeled posts on the blog
