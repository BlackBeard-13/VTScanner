# VTScanner

A small command-line tool that scans a file or a URL with the [VirusTotal](https://www.virustotal.com) API and saves the full analysis report as JSON.

## What it does

1. Checks that your VirusTotal API key is set and valid before doing anything else.
2. Asks whether you want to scan a **file** or a **URL**.
3. Submits it to VirusTotal and gets back an analysis ID.
4. Polls the analysis endpoint until the scan is `completed` (it waits between checks to stay within the free-tier rate limit).
5. Saves the full report to `results.json` to be used and/or imported.

## Requirements

- Python 3.8 or newer
- A free VirusTotal account and API key (found under your profile at virustotal.com)
- The `requests` library

## Installation

```bash
git clone https://github.com/BlackBeard-13/VTScanner.git
cd VTScanner
pip install -r requirements.txt
```

## Set your API key

The script reads your key from the `VT_API` environment variable. Never paste the key into the code or commit it to the repo.

**macOS / Linux** (current terminal session):
```bash
export VT_API="your_key_here"
```
To make it permanent, add that line to `~/.bashrc` or `~/.zshrc`.

**Windows (PowerShell, current session):**
```powershell
$env:VT_API = "your_key_here"
```

**Windows (persistent, reopen your terminal afterward):**
```
setx VT_API "your_key_here"
```

## Usage

```bash
python VT-tester.py
```

You'll see a menu:

```
What are you inputting:
1. File Name
2. URL Name
Which Option:
```

- **Option 1:** enter the path to a file. It is uploaded to VirusTotal for scanning.
- **Option 2:** enter a URL. VirusTotal scans the URL (the file is not downloaded by this tool).

While the scan runs, you'll see status lines such as `Status: queued (check 1/10). Waiting 20s...`. When it finishes, the report is written to `results.json`.

### Reading the results

Open `results.json` and look at `data.attributes.stats`. It contains counts of how many engines flagged the item as `malicious`, `suspicious`, `harmless` or `undetected`. The per-engine verdicts are under `data.attributes.results`.

A clean result means no engine flagged the item. It does not guarantee the item is safe, since new or targeted threats can go undetected.

## Project structure

```
VTScanner/
├── VT-tester.py          # Menu and entry point
├── VTfunctions/
│   ├── __init__.py
│   ├── vtfunctions.py    # API calls: key check, file/URL submit, polling
│   └── utils.py          # Helper functions (safe JSON parsing)
├── requirements.txt
├── .gitignore
└── README.md
```

## Limits and notes

- **Rate limit:** the free VirusTotal API allows about 4 requests per minute, with daily and monthly quotas. The tool waits 20 seconds between status checks to stay under the per-minute limit. If you hit a limit, wait a minute and try again.
- **File size:** the standard upload endpoint accepts files up to 32 MB.
- **Timeouts:** if a scan is still not complete after 10 checks, the tool stops and prints the analysis ID so you can look it up later.
- **Privacy:** files you upload to VirusTotal can be seen by the security community. Do not scan anything confidential.
- **Terms of use:** the free API is intended for non-commercial use. See [VirusTotal's terms](https://docs.virustotal.com/docs/terms-of-service) and use your own API key.

## Troubleshooting

| Message | Likely cause |
|---|---|
| `Error: Key is not found. Please set as environment variable` | The key isn't set in the terminal you're running from. set it and try again.|
| `API key Invalid (status 401/403)` | The key is wrong or was revoked. Check it on your VirusTotal profile. |
| `Rate limit or quota exceeded` | You've used your per-minute or daily quota. Wait and retry. |
| `Unable to reach VirusTotal` | No internet connection, or a network/proxy problem. |
| `That file does not exist.` | The path is wrong. Check it and try again. |

## Roadmap
   This code is a more simple script so there is not much currently planned
- SHA-256 hash lookup before upload, so already-known files aren't re-uploaded
- Adding the IP scan call to scan IP address as well

## License

MIT License, see LICENSE.txt
