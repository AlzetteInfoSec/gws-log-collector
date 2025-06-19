# Google Workspace Log Collector

> **Note:** This script is based on and inspired by the original [gws-get-logs.py](https://github.com/dlcowen/sansfor509/blob/main/GWS/gws-log-collection/gws-get-logs.py) script written by Megan Roddie-Fonseca and the [ALFA](https://github.com/invictus-ir/ALFA/tree/main) (Automated Log Forensics for Applications) tool by Invictus IR.

This script fetches Google Workspace audit logs for one or more applications, supporting both Service Account (automated) and OAuth (interactive) authentication methods. It supports initial and incremental (update) collections, deduplication, and produces stats files (CSV and JSON) for every run.

## Features
- Dual Authentication Support: Service Account (automated) and OAuth (interactive) authentication
- Complete Log Coverage: Supports all 22 Google Workspace applications including Keep and Vault logs
- Incremental Writing: Configurable write frequency to reduce memory usage for large collections
- Real-time Progress Display: Shows downloaded counts and status for each application during collection
- Collects logs for multiple Google Workspace applications in parallel
- Supports initial and update (incremental) collections
- Deduplicates log entries using timestamp and uniqueQualifier
- Outputs logs as JSON lines, one file per application
- Produces detailed stats files in both CSV and JSON format for every run, stored in the parent directory of the collection folder
- Multi-threaded for speed, with progress bars and verbosity control
- Comprehensive error handling and retry logic

## Authentication Methods

### Method 1: Service Account (Automated, Recommended for Automation)
Best for automated/scheduled collections. Requires domain-wide delegation setup.

### Method 2: OAuth (Interactive, Full Access)
Best for interactive use and accessing all log types. Supports all available applications including Keep logs.

## Authentication Method Comparison

| Feature | Service Account | OAuth |
|---------|----------------|-------|
| **Setup Complexity** | High (domain delegation) | Low (OAuth flow) |
| **User Interaction** | None (automated) | One-time setup |
| **Automation** | [+] Excellent | Limited (token refresh) |
| **Security** | High (service account) | High (OAuth) |

## Installation

Install dependencies (ideally in a virtual environment):

```sh
pip install -r requirements.txt
```

## Setup Options

### Option A: Service Account Setup

#### 1. Create a Google Cloud Project
- Go to [Google Cloud Console](https://console.cloud.google.com/)
- Create a new project (or use an existing one)

#### 2. Enable the Admin SDK API
- In your project, go to **APIs & Services > Library**
- Search for **Admin SDK API** and enable it

#### 3. Create a Service Account
- Go to **APIs & Services > Credentials**
- Click **Create Credentials > Service account**
- Give it a name (e.g., "GWS Log Collector")
- Grant it the **Project > Viewer** role (or leave blank)
- Click **Done**

#### 4. Create and Download a Service Account Key
- In the Service Accounts list, click your new account
- Go to the **Keys** tab
- Click **Add Key > Create new key**
- Choose **JSON** and download the file (keep it safe!)

#### 5. Configure Domain-Wide Delegation in Google Workspace
- In the Service Account details, enable **Domain-wide delegation**
- Note the **Client ID**
- In the [Google Admin Console](https://admin.google.com/):
  - Go to **Security > API Controls > Domain-wide Delegation**
  - Click **Add new** and enter the Client ID
  - Scopes: `https://www.googleapis.com/auth/admin.reports.audit.readonly`

### Option B: OAuth Setup

#### 1. Create a Google Cloud Project
- Go to [Google Cloud Console](https://console.cloud.google.com/)
- Create a new project (or use an existing one)

#### 2. Enable the Admin SDK API
- In your project, go to **APIs & Services > Library**
- Search for **Admin SDK API** and enable it

#### 3. Create OAuth Credentials
- Go to **APIs & Services > Credentials**
- Click **Create Credentials > OAuth client ID**
- Choose **Desktop application** as application type
- Download the JSON file and save it (e.g., `oauth_credentials.json`)

#### 4. Initialize OAuth (One-time)
```sh
python gws-log-collector.py --init --creds-path oauth_credentials.json
```

## Usage

### Service Account Authentication (Automated)
```sh
python gws-log-collector.py --auth-method service-account --creds-path <service-account.json> --delegated-creds <admin@yourdomain.com> --gws-domain <yourdomain.com> [options]
```

### OAuth Authentication (Interactive)
```sh
# One-time initialization
python gws-log-collector.py --init --creds-path <oauth_credentials.json>

# Log collection
python gws-log-collector.py --auth-method oauth --creds-path <oauth_credentials.json> --gws-domain <yourdomain.com> [options]
```

### Required Arguments

**For Service Account:**
- `--creds-path` : Path to the service account JSON file
- `--delegated-creds` : Email of a super-admin user in your Google Workspace domain
- `--gws-domain` : Your Google Workspace domain

**For OAuth:**
- `--creds-path` : Path to the OAuth credentials JSON file (for --init and log collection)
- `--gws-domain` : Your Google Workspace domain (for log collection)

### Common Options
- `--auth-method` : Authentication method (`service-account` or `oauth`, default: `service-account`)
- `--init` : Initialize OAuth credentials (required once before using OAuth)
- `--oauth-port` : Port for OAuth callback server (default: 8089)
- `--token-file` : Path to store OAuth token file (default: `token.json`)
- `--output-path` / `-o` : Main output directory for collection subfolders (default: current directory). The script will create a subfolder like `collection_<timestamp>_<collection_type>_<gws_domain>` inside this path.
- `--apps` / `-a` : Comma-separated list of applications or 'all' (default: 'all' - fetches from Google's discovery API)
- `--from-date` : Only fetch logs after this date (ignored in update mode if files exist)
- `--update` / `-u` : Path to an existing collection folder to update with new logs (requires --update-mode).
- `--update-mode` : **REQUIRED if --update is used.** Specifies the behavior for an update operation.
    - `append`: Deduplicate and write all unique records (old + new) to the files in the new collection folder.
    - `diff`: Only write new records found in this update to the files in the new collection folder (files will only contain new records from this run).
- `--max-results` : Max results per API call (default: 1000)
- `--threads` / `-t` : Number of parallel threads (default: 20)
- `--write-batch-size` : Write log entries to disk every N records to reduce memory usage for large collections. Set to 0 to write only at the end (default: 100000)
- `--no-progress` : Disable progress bars
- `--quiet` / `-q` : Minimal output
- `--verbose` / `-v` : Increase verbosity (can use multiple times)

### Examples

#### Service Account Examples

Initial collection:
```sh
python gws-log-collector.py --auth-method service-account --creds-path creds.json --delegated-creds admin@yourdomain.com --gws-domain yourdomain.com
```

Specific applications:
```sh
python gws-log-collector.py --auth-method service-account --creds-path creds.json --delegated-creds admin@yourdomain.com --gws-domain yourdomain.com --apps admin,login,drive,keep
```

Update collection (append mode):
```sh
python gws-log-collector.py --auth-method service-account --creds-path creds.json --delegated-creds admin@yourdomain.com --gws-domain yourdomain.com --update path/to/collection_<old_timestamp>_initial_yourdomain.com --update-mode append
```

#### OAuth Examples

One-time initialization:
```sh
python gws-log-collector.py --init --creds-path oauth_credentials.json
```

Initial collection:
```sh
python gws-log-collector.py --auth-method oauth --creds-path oauth_credentials.json --gws-domain yourdomain.com
```

Collect specific applications including Keep:
```sh
python gws-log-collector.py --auth-method oauth --creds-path oauth_credentials.json --gws-domain yourdomain.com --apps admin,login,drive,keep
```

Update collection (diff mode):
```sh
python gws-log-collector.py --auth-method oauth --creds-path oauth_credentials.json --gws-domain yourdomain.com --update path/to/collection_<old_timestamp>_initial_yourdomain.com --update-mode diff
```

Large collection with incremental writing and real-time progress display:
```sh
python gws-log-collector.py --auth-method oauth --creds-path oauth_credentials.json --gws-domain yourdomain.com --write-batch-size 50000 --verbose
```

## Supported Applications

The script automatically fetches the current list of supported applications from Google's API. Supported applications include:

- `access_transparency` - Access Transparency activities
- `admin` - Admin console activities
- `calendar` - Google Calendar activities
- `chat` - Google Chat activities
- `chrome` - Chrome activities
- `context_aware_access` - Context-aware access activities
- `data_studio` - Data Studio activities
- `drive` - Google Drive activities
- `gcp` - Google Cloud Platform activities
- `gplus` - Google+ activities
- `groups` - Google Groups activities
- `groups_enterprise` - Google Groups Enterprise activities
- `jamboard` - Jamboard activities
- `keep` - Google Keep activities
- `login` - User login activities
- `meet` - Google Meet activities
- `mobile` - Mobile device activities
- `rules` - Rules activities
- `saml` - SAML activities
- `token` - Token activities
- `user_accounts` - User account activities
- `vault` - Google Vault activities

Use `--apps all` (default) to collect all available applications, or specify a comma-separated list.

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

## Requirements

- Python 3.7+
- Google API Client Library v2.35.0 or higher (for Keep logs support)
- Valid Google Workspace domain with admin access
- Either:
  - Service account with domain-wide delegation, OR
  - OAuth credentials for interactive authentication

## Notes
- The script is multi-threaded and can be run repeatedly for incremental updates.
- **Important**: Google API Client Library v2.35.0 or higher is required for Keep logs support.
- OAuth authentication provides access to all log types, including Keep logs.
- Service Account authentication now also supports Keep logs with the updated API version.
- Stats files are sorted by application name for easy comparison.
- For more details, run:
  ```sh
  python gws-log-collector.py --help
  ```

## Troubleshooting

### Keep Logs Not Available
If you see "Application 'keep' not supported", ensure you have:
1. Google API Client Library v2.35.0 or higher: `pip install google-api-python-client>=2.35.0`
2. For Service Account: Proper domain-wide delegation configured
3. For OAuth: Completed the one-time `--init` setup

### OAuth Issues
If OAuth initialization fails:
1. Ensure you've created "Desktop application" OAuth credentials
2. Check that Admin SDK API is enabled in your Google Cloud project
3. Try revoking previous authorizations at https://myaccount.google.com/permissions