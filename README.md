# Google Workspace Log Collector

> **Note:** This script is based on and inspired by the original [gws-get-logs.py](https://github.com/dlcowen/sansfor509/blob/main/GWS/gws-log-collection/gws-get-logs.py) script written by Megan Roddie-Fonseca and the [ALFA](https://github.com/invictus-ir/ALFA/tree/main) (Automated Log Forensics for Applications) tool by Invictus IR.

This script fetches Google Workspace audit logs for one or more applications, supporting both Service Account (automated) and OAuth (interactive) authentication methods. It supports initial and incremental (update) collections, deduplication, and produces stats files (CSV and JSON) for every run.

## Features
- **Dual Authentication Support**: Service Account (automated) and OAuth (interactive) authentication
- **Complete Log Coverage**: Supports all 23+ Google Workspace applications including Keep, Vault, and Gemini logs
- **Structured Real-time Output**: Clean, timestamped progress display with ISO8601 UTC timestamps and consistent formatting
- **Advanced Verbose Mode**: Multi-level verbosity with structured output (`-v`, `-vv`, `-vvv`) for detailed debugging
- **Complete CLI Audit Trail**: Every terminal output saved to timestamped text file for compliance and debugging
- **Real-time Error Display**: Errors are shown immediately during collection with proper formatting
- **Incremental Writing**: Configurable write frequency to reduce memory usage for large collections
- **Multi-threaded Collection**: Parallel processing with detailed progress tracking for each application
- **Update Collections**: Supports incremental updates with append or diff modes
- **Deduplication**: Automatic deduplication using timestamp and uniqueQualifier
- **Comprehensive Stats**: Detailed CSV and JSON stats files for every collection with file integrity hashes
- **Robust Error Handling**: Automatic retry logic with exponential backoff

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
- `--to-date` : Only fetch logs before this date (can be combined with --from-date for date range filtering)
- `--update` / `-u` : Path to an existing collection folder to update with new logs (requires --update-mode).
- `--update-mode` : **REQUIRED if --update is used.** Specifies the behavior for an update operation.
    - `append`: Deduplicate and write all unique records (old + new) to the files in the new collection folder.
    - `diff`: Only write new records found in this update to the files in the new collection folder (files will only contain new records from this run).
- `--max-results` : Max results per API call (default: 1000)
- `--threads` / `-t` : Number of parallel threads (default: 20)
- `--write-batch-size` : Write log entries to disk every N records to reduce memory usage for large collections. Set to 0 to write only at the end (default: 100000)
- `--no-progress` : Disable progress display (not recommended)
- `--quiet` / `-q` : Minimal output (errors and final summary only)
- `--verbose` / `-v` : Increase verbosity (can use multiple times: `-v`, `-vv`, `-vvv`)

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

Date range collection (from January 1st to January 31st, 2025):
```sh
python gws-log-collector.py --auth-method service-account --creds-path creds.json --delegated-creds admin@yourdomain.com --gws-domain yourdomain.com --from-date 2025-01-01 --to-date 2025-02-01
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

Collect logs for the last week only:
```sh
python gws-log-collector.py --auth-method oauth --creds-path oauth_credentials.json --gws-domain yourdomain.com --from-date 2025-01-15 --to-date 2025-01-22
```

Update collection (diff mode):
```sh
python gws-log-collector.py --auth-method oauth --creds-path oauth_credentials.json --gws-domain yourdomain.com --update path/to/collection_<old_timestamp>_initial_yourdomain.com --update-mode diff
```

Large collection with incremental writing and real-time progress display:
```sh
python gws-log-collector.py --auth-method oauth --creds-path oauth_credentials.json --gws-domain yourdomain.com --write-batch-size 50000 --verbose
```

## Verbose Mode Levels

The script supports multiple verbosity levels for detailed debugging and monitoring:

### **Default (no flags)**: Basic Progress
- Shows application completion status
- Progress updates for overall collection
- Final execution summary

### **`-v` (Level 1)**: Standard Verbose
- All default output plus:
- Authentication details and configuration
- Collection start/completion messages
- Stats file creation notifications

### **`-vv` (Level 2)**: Detailed Verbose  
- All Level 1 output plus:
- Thread initialization and API session details
- Date filtering information for each application
- File operation details and record counts
- Incremental writing progress for large collections

### **`-vvv` (Level 3)**: Maximum Debug
- All Level 2 output plus:
- Page-by-page API fetch details
- Configuration dump showing all parameters
- Individual entry processing information
- API retry attempts and timing details

**Example with maximum verbosity:**
```sh
python gws-log-collector.py --auth-method oauth --creds-path oauth_credentials.json --gws-domain yourdomain.com -vvv
```

## Output Format

The script provides structured, real-time output with ISO8601 UTC timestamps:

### Console Output Format
```
[timestamp] | status       | application/progress       | details
[2025-07-11T142051Z] | DONE         | access_transparency       | 0 activities
[2025-07-11T142051Z] | DONE         | admin                     | 914 activities
[2025-07-11T142056Z] | PROGRESS     | Overall Progress          | 19/23 apps done (83%) [Elapsed: 10.7s]
[2025-07-11T142209Z] | DOWNLOADING  | token                     | 100000 activities
[2025-07-11T142105Z] | ERROR        | ERROR                     | Application 'invalid_app' is not supported...
```

### Status Types
- **DONE**: Application collection completed
- **DOWNLOADING**: Intermediate progress during large collections  
- **PROGRESS**: Overall collection progress updates
- **ERROR**: Error messages with immediate display
- **WARNING/INFO/DEBUG**: Additional messages based on verbosity level

### CLI Output Audit Trail

Every collection run generates a complete audit trail saved as `_stats_cli_output_<timestamp>_<collection_type>_<domain>.txt`:

- **Complete Terminal Output**: Exact copy of everything displayed during execution
- **Structured Formatting**: All messages follow the consistent `[timestamp] | level | context | message` format
- **Execution Summary Included**: Full summary with timing, statistics, and file locations
- **Compliance Ready**: Perfect for audit trails, debugging, and forensic documentation
- **Timestamped**: Uses ISO8601 UTC timestamps for precise timing correlation

The audit file contains everything you see on screen plus maintains perfect formatting for easy parsing and analysis.

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
- `gemini_in_workspace_apps` - Gemini in Google Workspace activities
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

### Collection Folder Structure
Everything related to a collection is organized in a single folder:
```
collection_2025-08-13T201022Z_initial_alzetteinfosec.com/
├── admin.json                                      # Application log files
├── drive.json
├── token.json
├── ...
├── _stats_2025-08-13T201022Z_initial_...csv        # Stats (CSV format)
├── _stats_2025-08-13T201022Z_initial_...json       # Stats (JSON format)
└── _stats_cli_output_2025-08-13T201022Z_...txt     # CLI output log
```

### File Details
- **Log files**: One JSON file per application inside the collection folder
  - In `diff` update mode, these files only contain new records from the current run
  - In `append` update mode, these files contain all unique records (old + new)
- **Stats files**: CSV and JSON files with collection metadata and file information
  - Columns/keys: `application`, `file_path`, `record_count`, `updated_record_count`, `file_size`, `md5`, `sha1`, `collection_time`, `initial_collection_time`, `collection_type`, `original_update_path`
  - Includes MD5 and SHA1 hashes for file integrity verification
- **CLI Output file**: Complete audit trail of terminal output with structured formatting
  - Exact copy of all console output with consistent timestamp formatting
  - Includes execution summary, progress updates, and error messages
  - Perfect for compliance documentation and debugging
  - Uses ISO8601 UTC timestamps throughout
- The `collection_type` in names and stats will indicate `initial`, `update-append`, or `update-diff`

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
- All output uses structured, consistent formatting with ISO8601 UTC timestamps for professional logging.
- CLI audit trails provide complete execution records suitable for compliance and forensic analysis.
- Stats files are sorted by application name for easy comparison.
- Verbose mode provides granular control over output detail level for debugging and monitoring.
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