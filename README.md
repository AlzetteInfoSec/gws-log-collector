# Google Workspace Log Collector

> **Note:** This script is based on and inspired by the original [gws-get-logs.py](https://github.com/dlcowen/sansfor509/blob/main/GWS/gws-log-collection/gws-get-logs.py) script written by Megan Roddie-Fonseca.

This script fetches Google Workspace audit logs for one or more applications, using a Google Cloud service account with domain-wide delegation. It supports initial and incremental (update) collections, deduplication, and produces stats files (CSV and JSON) for every run.

## Features
- Collects logs for multiple Google Workspace applications in parallel
- Supports initial and update (incremental) collections
- Deduplicates log entries using timestamp and uniqueQualifier
- Outputs logs as JSON lines, one file per application
- Produces detailed stats files in both CSV and JSON format for every run, stored in the parent directory of the collection folder.
- Multi-threaded for speed, with progress bars and verbosity control

## Setup: Google Cloud and Google Workspace

### 1. Create a Google Cloud Project
- Go to [Google Cloud Console](https://console.cloud.google.com/)
- Create a new project (or use an existing one)

### 2. Enable the Admin SDK API
- In your project, go to **APIs & Services > Library**
- Search for **Admin SDK API** and enable it

### 3. Create a Service Account
- Go to **APIs & Services > Credentials**
- Click **Create Credentials > Service account**
- Give it a name (e.g., "GWS Log Collector")
- Grant it the **Project > Viewer** role (or leave blank)
- Click **Done**

### 4. Create and Download a Service Account Key
- In the Service Accounts list, click your new account
- Go to the **Keys** tab
- Click **Add Key > Create new key**
- Choose **JSON** and download the file (keep it safe!)

### 5. Configure Domain-Wide Delegation in Google Workspace
- In the Service Account details, enable **Domain-wide delegation**
- Note the **Client ID**
- In the [Google Admin Console](https://admin.google.com/):
  - Go to **Security > API Controls > Domain-wide Delegation**
  - Click **Add new** and enter the Client ID
  - Scopes: `https://www.googleapis.com/auth/admin.reports.audit.readonly,https://www.googleapis.com/auth/apps.alerts`

## Installation

Install dependencies (ideally in a virtual environment):

```sh
pip install -r requirements.txt
```

## Usage

```sh
python gws-log-collector.py --creds-path <service-account.json> --delegated-creds <admin@yourdomain.com> --gws-domain <yourdomain.com> [options]
```

### Required Arguments
- `--creds-path` : Path to the service account JSON file
- `--delegated-creds` : Email of a super-admin user in your Google Workspace domain
- `--gws-domain` : Your Google Workspace domain (used in output folder and stats file names)

### Common Options
- `--output-path` / `-o` : Main output directory for collection subfolders (default: current directory). The script will create a subfolder like `collection_<timestamp>_<collection_type>_<gws_domain>` inside this path.
- `--apps` / `-a` : Comma-separated list of applications (or 'all')
- `--from-date` : Only fetch logs after this date (ignored in update mode if files exist)
- `--update` / `-u` : Path to an existing collection folder to update with new logs (requires --update-mode).
- `--update-mode` : **REQUIRED if --update is used.** Specifies the behavior for an update operation.
    - `append`: Deduplicate and write all unique records (old + new) to the files in the new collection folder.
    - `diff`: Only write new records found in this update to the files in the new collection folder (files will only contain new records from this run).
- `--max-results` : Max results per API call (default: 1000)
- `--threads` / `-t` : Number of parallel threads (default: 20)
- `--batch-size` : Buffer size before writing to disk (default: 10000)
- `--no-progress` : Disable progress bars
- `--quiet` / `-q` : Minimal output
- `--verbose` / `-v` : Increase verbosity (can use multiple times)

### Example

Initial collection:
```sh
python gws-log-collector.py --creds-path creds.json --delegated-creds admin@yourdomain.com --gws-domain yourdomain.com
# Collection folder (in current dir): collection_<timestamp>_initial_yourdomain.com/
# Stats files (in current dir): _stats_<timestamp>_initial_yourdomain.com.csv
#                               _stats_<timestamp>_initial_yourdomain.com.json
```

Update collection (append mode):
```sh
python gws-log-collector.py --creds-path creds.json --delegated-creds admin@yourdomain.com --gws-domain yourdomain.com --update path/to/collection_<old_timestamp>_initial_yourdomain.com --update-mode append
# New collection folder (in current dir): collection_<new_timestamp>_update-append_yourdomain.com/
# Stats files (in current dir): _stats_<new_timestamp>_update-append_yourdomain.com.csv
#                               _stats_<new_timestamp>_update-append_yourdomain.com.json
```

Update collection (diff mode, default):
```sh
python gws-log-collector.py --creds-path creds.json --delegated-creds admin@yourdomain.com --gws-domain yourdomain.com --update path/to/collection_<old_timestamp>_initial_yourdomain.com --update-mode diff
# New collection folder (in current dir): collection_<new_timestamp>_update-diff_yourdomain.com/
# Stats files (in current dir): _stats_<new_timestamp>_update-diff_yourdomain.com.csv
#                               _stats_<new_timestamp>_update-diff_yourdomain.com.json
```

## Output
- Log files: One JSON file per application inside the collection folder (e.g., `collection_<timestamp>_<collection_type>_<gws_domain>/drive.json`).
  - In `diff` update mode, these files only contain new records from the current run.
  - In `append` update mode, these files contain all unique records (old + new).
- Stats files: Stored in the parent directory of the collection folder.
  - CSV: `_stats_<timestamp>_<collection_type>_<gws_domain>.csv`
  - JSON: `_stats_<timestamp>_<collection_type>_<gws_domain>.json`
  - Columns/keys in stats files:
    - `application`, `file_path`, `record_count`, `updated_record_count`, `file_size`, `md5`, `sha1`, `collection_time`, `initial_collection_time`, `collection_type`, `original_update_path`
- The `collection_type` in names and stats will indicate `initial`, `update-append`, or `update-diff`.

## Notes
- The script is multi-threaded and can be run repeatedly for incremental updates.
- Stats files are sorted by application name for easy comparison.
- For more details, run:
  ```sh
  python gws-log-collector.py --help
  ```