# Google Workspace Log Collector

> **Note:** This script is based on and inspired by the original [gws-get-logs.py](https://github.com/dlcowen/sansfor509/blob/main/GWS/gws-log-collection/gws-get-logs.py) script written by Megan Roddie-Fonseca and the [ALFA](https://github.com/invictus-ir/ALFA/tree/main) (Automated Log Forensics for Applications) tool by Invictus IR.

This script fetches Google Workspace audit logs for one or more applications, supporting both Service Account (automated) and OAuth (interactive) authentication methods. It supports initial and incremental (update) collections, deduplication, and produces stats files (CSV and JSON) for every run.

In addition to the Admin SDK Reports API, the script can export richer audit logs and Drive inventory data directly from BigQuery using the `--bigquery` mode.

## Features
- **Dual Authentication Support**: Service Account (automated) and OAuth (interactive) authentication
- **Dual Data Source**: Admin SDK Reports API (default) or BigQuery export (`--bigquery`)
- **BigQuery Audit Log Export**: Export full-fidelity Workspace audit logs from BigQuery, including fields not available in the Admin SDK (e.g. Gmail post-delivery interactions with link URLs)
- **Drive Inventory Export**: Export Drive file metadata and shared drive information from BigQuery (`--drive-inventory`)
- **Complete Log Coverage**: Supports all 38 Google Workspace applications including Gmail, Takeout, LDAP, and Gemini logs
- **Structured Real-time Output**: Clean, timestamped progress display with ISO8601 UTC timestamps and consistent formatting
- **Advanced Verbose Mode**: Multi-level verbosity with structured output (`-v`, `-vv`, `-vvv`) for detailed debugging
- **Complete CLI Audit Trail**: Every terminal output saved to timestamped text file for compliance and debugging
- **Real-time Error Display**: Errors are shown immediately during collection with proper formatting
- **Incremental Writing**: Configurable write frequency to reduce memory usage for large collections
- **Multi-threaded Collection**: Parallel processing with detailed progress tracking for each application
- **Update Collections**: Supports incremental updates with append or diff modes (both Admin SDK and BigQuery)
- **Deduplication**: Automatic deduplication using timestamp/uniqueQualifier (Admin SDK) or full-row hash (BigQuery)
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

For faster BigQuery reads, optionally install `pyarrow`:

```sh
pip install pyarrow
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

### Option C: BigQuery Export Setup (Additional)

BigQuery mode uses the **same credentials** from Option A or B above, with additional GCP configuration.

#### 1. Enable the BigQuery API
- In your Google Cloud project, go to **APIs & Services > Library**
- Search for **BigQuery API** and enable it
- (Optional) Also enable **BigQuery Storage API** for faster reads if you installed `pyarrow`

#### 2. Configure Workspace BigQuery Export
- In the [Google Admin Console](https://admin.google.com/), go to **Reporting > Data integrations**
- Set up **BigQuery export** — choose a GCP project and dataset name
- (Optional) Enable **Drive inventory export** in the same section

#### 3. Grant Access to the Service Account or OAuth User

**For Service Account:**
- In the [Google Cloud Console](https://console.cloud.google.com/), go to **IAM & Admin > IAM**
- Grant your service account these roles on the BigQuery project:
  - `BigQuery Data Viewer` (`roles/bigquery.dataViewer`)
  - `BigQuery Job User` (`roles/bigquery.jobUser`)
- Domain-wide delegation is **not** needed for BigQuery access

**For OAuth:**
- The authenticated user needs BigQuery access to the project/dataset
- When running `--init` with `--bigquery`, the BigQuery scope is automatically included:
  ```sh
  python gws-log-collector.py --init --creds-path oauth_credentials.json --bigquery
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

### BigQuery Mode — Service Account
```sh
python gws-log-collector.py --bigquery --bq-project <gcp-project-id> --bq-dataset <dataset> --creds-path <service-account.json> --gws-domain <yourdomain.com> [options]
```

### BigQuery Mode — OAuth
```sh
python gws-log-collector.py --bigquery --bq-project <gcp-project-id> --bq-dataset <dataset> --auth-method oauth --creds-path <oauth_credentials.json> --gws-domain <yourdomain.com> [options]
```

### Required Arguments

**For Service Account (Admin SDK):**
- `--creds-path` : Path to the service account JSON file
- `--delegated-creds` : Email of a super-admin user in your Google Workspace domain
- `--gws-domain` : Your Google Workspace domain

**For Service Account (BigQuery):**
- `--creds-path` : Path to the service account JSON file
- `--gws-domain` : Your Google Workspace domain
- `--bq-project` : GCP project ID containing the BigQuery dataset
- `--bq-dataset` : BigQuery dataset name (e.g. `gws_logs`)
- `--delegated-creds` is **not** required for BigQuery mode

**For OAuth:**
- `--creds-path` : Path to the OAuth credentials JSON file (for --init and log collection)
- `--gws-domain` : Your Google Workspace domain (for log collection)

### Common Options
- `--auth-method` : Authentication method (`service-account` or `oauth`, default: `service-account`)
- `--init` : Initialize OAuth credentials (required once before using OAuth)
- `--oauth-port` : Port for OAuth callback server (default: 8089)
- `--token-file` : Path to store OAuth token file (default: `token.json`)
- `--output-path` / `-o` : Main output directory for collection subfolders (default: current directory). The script will create a subfolder like `collection_<timestamp>_<source>_<collection_type>_<gws_domain>` inside this path, where `<source>` is `api` or `bigquery`.
- `--apps` / `-a` : Comma-separated list of applications or 'all' (default: 'all' - fetches from Google's discovery API, or from BigQuery `record_type` values in `--bigquery` mode)
- `--from-date` : Only fetch logs after this date (ignored in update mode if files exist)
- `--to-date` : Only fetch logs before this date (can be combined with --from-date for date range filtering)
- `--update` / `-u` : Path to an existing collection folder to update with new logs (requires --update-mode).
- `--update-mode` : **REQUIRED if --update is used.** Specifies the behavior for an update operation.
    - `append`: Deduplicate and write all unique records (old + new) to the files in the new collection folder.
    - `diff`: Only write new records found in this update to the files in the new collection folder (files will only contain new records from this run).
- `--max-results` : Max results per API call (default: 1000, Admin SDK only)
- `--threads` / `-t` : Number of parallel threads (default: 20)
- `--write-batch-size` : Write log entries to disk every N records to reduce memory usage for large collections. Set to 0 to write only at the end (default: 100000, Admin SDK only)
- `--no-progress` : Disable progress display (not recommended)
- `--quiet` / `-q` : Minimal output (errors and final summary only)
- `--verbose` / `-v` : Increase verbosity (can use multiple times: `-v`, `-vv`, `-vvv`)

### BigQuery Mode Options
- `--bigquery` : Enable BigQuery mode — export logs from BigQuery instead of the Admin SDK Reports API
- `--bq-project` : GCP project ID containing the BigQuery dataset (required with `--bigquery`)
- `--bq-dataset` : BigQuery dataset name (required with `--bigquery`)
- `--drive-inventory` : Additionally export Drive inventory tables (`inventory` and `shared_drives`) alongside audit logs. Requires `--bigquery`.

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

#### BigQuery Examples

Export all audit logs from BigQuery (service account):
```sh
python gws-log-collector.py --bigquery --bq-project my-gcp-project --bq-dataset gws_logs --creds-path creds.json --gws-domain yourdomain.com
```

Export only Gmail and Drive logs from BigQuery:
```sh
python gws-log-collector.py --bigquery --bq-project my-gcp-project --bq-dataset gws_logs --creds-path creds.json --gws-domain yourdomain.com --apps gmail,drive
```

Export all audit logs from a specific date range:
```sh
python gws-log-collector.py --bigquery --bq-project my-gcp-project --bq-dataset gws_logs --creds-path creds.json --gws-domain yourdomain.com --from-date 2025-06-01 --to-date 2025-07-01
```

Export the entire BigQuery dataset (no date filter):
```sh
python gws-log-collector.py --bigquery --bq-project my-gcp-project --bq-dataset gws_logs --creds-path creds.json --gws-domain yourdomain.com
```

Export audit logs plus Drive inventory:
```sh
python gws-log-collector.py --bigquery --bq-project my-gcp-project --bq-dataset gws_logs --creds-path creds.json --gws-domain yourdomain.com --drive-inventory
```

Export only Drive inventory (specific apps not specified):
```sh
python gws-log-collector.py --bigquery --bq-project my-gcp-project --bq-dataset gws_logs --creds-path creds.json --gws-domain yourdomain.com --drive-inventory
```

BigQuery with OAuth:
```sh
python gws-log-collector.py --bigquery --bq-project my-gcp-project --bq-dataset gws_logs --auth-method oauth --creds-path oauth_credentials.json --gws-domain yourdomain.com
```

Update an existing BigQuery collection (append mode):
```sh
python gws-log-collector.py --bigquery --bq-project my-gcp-project --bq-dataset gws_logs --creds-path creds.json --gws-domain yourdomain.com --update path/to/collection_<old_timestamp>_initial_yourdomain.com --update-mode append
```

Update an existing BigQuery collection (diff mode — only new records):
```sh
python gws-log-collector.py --bigquery --bq-project my-gcp-project --bq-dataset gws_logs --creds-path creds.json --gws-domain yourdomain.com --update path/to/collection_<old_timestamp>_initial_yourdomain.com --update-mode diff
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

The script automatically fetches the current list of supported applications from Google's API discovery endpoint. As of January 2026, supported applications include:

- `access_evaluation` - Access evaluation activities
- `access_transparency` - Access Transparency activities
- `admin` - Admin console activities
- `admin_data_action` - Admin data action activities
- `assignments` - Assignments activities
- `calendar` - Google Calendar activities
- `chat` - Google Chat activities
- `chrome` - Chrome activities
- `classroom` - Google Classroom activities
- `cloud_search` - Cloud Search activities
- `contacts` - Contacts activities
- `context_aware_access` - Context-aware access activities
- `data_migration` - Data migration activities
- `data_studio` - Data Studio activities
- `directory_sync` - Directory sync activities
- `drive` - Google Drive activities
- `gcp` - Google Cloud Platform activities
- `gemini_in_workspace_apps` - Gemini in Google Workspace activities
- `gmail` - Gmail activities (requires date range, max 30 days)
- `gplus` - Google+ activities
- `graduation` - Graduation activities
- `groups` - Google Groups activities
- `groups_enterprise` - Google Groups Enterprise activities
- `jamboard` - Jamboard activities
- `keep` - Google Keep activities
- `ldap` - LDAP activities
- `login` - User login activities
- `meet` - Google Meet activities
- `meet_hardware` - Meet hardware activities
- `mobile` - Mobile device activities
- `profile` - Profile activities
- `rules` - Rules activities
- `saml` - SAML activities
- `takeout` - Google Takeout activities
- `tasks` - Google Tasks activities
- `token` - Token activities
- `user_accounts` - User account activities
- `vault` - Google Vault activities

> **Note**: The application list is fetched dynamically from Google's API, so new log types will be automatically available as Google adds them.

Use `--apps all` (default) to collect all available applications, or specify a comma-separated list.

## Output

### Collection Folder Structure
Everything related to a collection is organized in a single folder:

**Admin SDK mode:**
```
collection_2025-08-13T201022Z_api_initial_yourdomain.com/
├── admin.json                                          # Application log files (NDJSON)
├── drive.json
├── token.json
├── ...
├── _stats_..._api_initial_yourdomain.com.csv           # Stats (CSV format)
├── _stats_..._api_initial_yourdomain.com.json          # Stats (JSON format)
└── _stats_cli_output_..._api_initial_yourdomain.com.txt  # CLI output log
```

**BigQuery mode (with --drive-inventory):**
```
collection_2025-08-13T201022Z_bigquery_initial_yourdomain.com/
├── admin.json                                          # Audit log files per record_type (NDJSON)
├── drive.json
├── gmail.json
├── login.json
├── ...
├── drive_inventory.json                                # Drive inventory export (NDJSON)
├── drive_shared_drives.json                            # Shared drives export (NDJSON)
├── _stats_..._bigquery_initial_yourdomain.com.csv      # Stats (CSV format)
├── _stats_..._bigquery_initial_yourdomain.com.json     # Stats (JSON format)
└── _stats_cli_output_..._bigquery_initial_yourdomain.com.txt  # CLI output log
```

### File Details
- **Log files**: One NDJSON file per application/record_type inside the collection folder
  - In `diff` update mode, these files only contain new records from the current run
  - In `append` update mode, these files contain all unique records (old + new)
  - In BigQuery mode, rows retain the full BigQuery schema (nested fields like `gmail.message_info.*`)
- **Drive inventory files** (BigQuery mode with `--drive-inventory`):
  - `drive_inventory.json` — one row per Drive item (file metadata, permissions, labels)
  - `drive_shared_drives.json` — one row per shared drive (ID, name)
  - These are always full snapshots (no date filtering or deduplication)
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
- Google API Client Library v2.187.0 or higher (for all log types including Takeout, LDAP, Gmail)
- Valid Google Workspace domain with admin access
- Either:
  - Service account with domain-wide delegation, OR
  - OAuth credentials for interactive authentication

**Additional for BigQuery mode (`--bigquery`):**
- `google-cloud-bigquery` v3.27.0 or higher (included in `requirements.txt`)
- (Optional) `pyarrow` for faster BigQuery Storage API reads
- BigQuery API enabled in your GCP project
- Google Workspace BigQuery export configured in the Admin Console (Reporting > Data integrations)
- Service account needs `BigQuery Data Viewer` + `BigQuery Job User` roles (no domain delegation needed), OR OAuth user needs BigQuery access

## Notes
- The script is multi-threaded and can be run repeatedly for incremental updates.
- **Dynamic Discovery**: The script uses `static_discovery=False` to fetch the latest API schema from Google, ensuring new log types are automatically supported.
- OAuth and Service Account authentication both provide access to all log types.
- All output uses structured, consistent formatting with ISO8601 UTC timestamps for professional logging.
- CLI audit trails provide complete execution records suitable for compliance and forensic analysis.
- Stats files are sorted by application name for easy comparison.
- Verbose mode provides granular control over output detail level for debugging and monitoring.
- **BigQuery mode** exports the full BigQuery row schema, which includes nested fields not available in the Admin SDK Reports API (e.g. `gmail.message_info.post_delivery_info.interaction.link_url` for link-click events).
- **BigQuery date filtering** uses `_PARTITIONTIME` and `time_usec` for cost-efficient queries. When no date range is specified, the entire dataset is exported.
- **Drive inventory** is always exported as a full snapshot regardless of `--from-date`/`--to-date` or `--update` mode.
- **BigQuery deduplication** (for `--update --update-mode append`) uses a SHA-256 hash of the full serialized row, since BigQuery rows lack the `id.time` + `id.uniqueQualifier` structure of Admin SDK responses.
- For more details, run:
  ```sh
  python gws-log-collector.py --help
  ```

## Troubleshooting

### Application Not Supported Errors
If you see "Application 'X' not supported" errors:
1. Ensure you have Google API Client Library v2.187.0 or higher: `pip install -r requirements.txt`
2. The script uses dynamic discovery to fetch supported applications - check your network connection
3. Some applications may return 0 records if there's no activity data (this is normal, not an error)
4. For Service Account: Ensure domain-wide delegation is properly configured with scope `https://www.googleapis.com/auth/admin.reports.audit.readonly`

### Gmail Logs
Gmail logs require both start and end dates with a maximum 30-day range. When no dates are specified, the script automatically uses the last 30 days from execution time.

### OAuth Issues
If OAuth initialization fails:
1. Ensure you've created "Desktop application" OAuth credentials
2. Check that Admin SDK API is enabled in your Google Cloud project
3. Try revoking previous authorizations at https://myaccount.google.com/permissions

### BigQuery Mode Issues

**"google-cloud-bigquery is not installed"**
- Run `pip install google-cloud-bigquery` (or `pip install -r requirements.txt`)

**Permission errors**
- Service account needs `BigQuery Data Viewer` + `BigQuery Job User` on the GCP project
- Domain-wide delegation is **not** needed for BigQuery — these are standard IAM roles
- For OAuth: ensure your user has BigQuery access, and re-run `--init --bigquery` to include the BigQuery scope

**Empty results or missing tables**
- Verify the BigQuery export is configured in the Admin Console: **Reporting > Data integrations**
- Check that the `--bq-project` and `--bq-dataset` match what is configured in the Admin Console
- BigQuery export may take up to 24 hours to populate initial data after first enabling it
- Use `--apps all` (default) to discover which `record_type` values exist in your dataset

**Drive inventory tables not found**
- Drive inventory export must be separately enabled in the Admin Console under **Reporting > Data integrations**
- The `inventory` and `shared_drives` tables are created in the dataset you configured