#!/usr/bin/env python3
import json
import requests
import os
import argparse
import logging
import threading
import time
import sys
import csv
import hashlib
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from googleapiclient.discovery import build
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from dateutil import parser as dateparser, tz
from googleapiclient.errors import HttpError
import shutil
import traceback

# Google Workspace Log Collector
#
# Supports two authentication methods:
# 1. Service Account (default) - Automated, requires service account delegation, some log types may not be available
# 2. OAuth - Interactive, supports all log types including Keep logs, requires user interaction
#
# Based on and inspired by the original gws-get-logs.py script by Megan Roddie-Fonseca:
# https://github.com/dlcowen/sansfor509/blob/main/GWS/gws-log-collection/gws-get-logs.py

class Google(object):
    """
    Class for connecting to API and retrieving logs
    """

    # These applications will be collected by default
    # Note: 'gmail' requires both startTime and endTime parameters and max 30-day range
    DEFAULT_APPLICATIONS = ['access_transparency', 'admin', 'calendar', 'chat', 'chrome', 'context_aware_access', 'classroom', 'data_studio', 'drive', 'gcp', 'gemini_in_workspace_apps', 'gmail', 'gplus', 'groups', 'groups_enterprise', 'jamboard', 'keep', 'login', 'meet', 'mobile', 'rules', 'saml', 'token', 'user_accounts', 'vault']
    
    # Applications that require both startTime and endTime (and max 30-day range)
    APPS_REQUIRING_DATE_RANGE = ['gmail']
    
    # Note: We no longer pre-filter applications. The API discovery endpoint may list
    # applications that aren't fully documented but may still work. We attempt to
    # fetch logs for all applications returned by the discovery endpoint and let
    # the API tell us which ones are actually supported/available for the account.
    
    # API retry settings
    RETRY_MAX_ATTEMPTS = 5
    RETRY_INITIAL_DELAY = 1
    RETRY_BACKOFF_FACTOR = 2
    RETRY_MAX_DELAY = 60

    def __init__(self, **kwargs):
        self.creds_path = kwargs['creds_path']
        self.auth_method = kwargs.get('auth_method', 'service-account')
        self.delegated_creds = kwargs.get('delegated_creds')  # Only needed for service account
        self.output_path = kwargs['output_path']
        self.app_list = kwargs['apps']
        self.update = kwargs['update']
        self.max_results = kwargs.get('max_results', 1000)  # Default API page size
        self.num_threads = kwargs.get('num_threads', 20)    # Default 20 threads
        self.verbosity = kwargs.get('verbosity', 1)         # Default verbosity level
        self.write_batch_size = kwargs.get('write_batch_size', 100000)  # Write to disk every N events
        self.gws_domain = kwargs['gws_domain']
        self.update_mode = kwargs.get('update_mode', None)
        self.original_update_path = kwargs.get('original_update_path', None)
        self.collection_timestamp = kwargs['consistent_timestamp'] # Use passed consistent timestamp
        
        # OAuth specific settings
        self.oauth_port = kwargs.get('oauth_port', 8089)
        self.token_file = os.path.abspath(kwargs.get('token_file', 'token.json'))
        
        # Initialize locks early (needed for OAuth logging)
        self.log_lock = threading.Lock()
        self.stats_lock = threading.Lock()
        
        # Initialize CLI output logging early (needed for _queue_message calls)
        self.cli_output_buffer = []  # Store all CLI output for later writing to file
        
        # Import any pre-initialization CLI output from global buffer
        global _global_cli_buffer
        if _global_cli_buffer:
            self.cli_output_buffer.extend(_global_cli_buffer)
        
        # Initialize credentials during startup (main thread)
        self._credentials = None
        if self.auth_method == 'oauth':
            if self.verbosity >= 1:
                self._queue_message("Initializing OAuth authentication...", 'info')
            # Set up OAuth credentials now in the main thread
            SCOPES = ['https://www.googleapis.com/auth/admin.reports.audit.readonly']
            self._credentials = self._get_oauth_credentials(SCOPES)
            if self.verbosity >= 1:
                self._queue_message("OAuth authentication completed successfully", 'info')
        
        # Collection type - used in folder and file names
        if self.update:
            if self.update_mode == 'diff':
                self.collection_type = 'update-diff'
            else:
                self.collection_type = 'update-append'
        else:
            self.collection_type = 'initial'
        
        # Generate timestamp for stats file
        self.collection_timestamp = datetime.now(tz=tz.tzutc()).strftime('%Y-%m-%dT%H%M%SZ')
        
        # For stats: set original_update_path for each row
        if self.update:
            self.stats_original_update_path = self.original_update_path
        else:
            self.stats_original_update_path = self.output_path
        
        # Stats filename includes consistent timestamp, collection type, and gws_domain.
        self.stats_filename = f"_stats_{self.collection_timestamp}_{self.collection_type}_{self.gws_domain}.csv"
        self.stats_json_filename = f"_stats_{self.collection_timestamp}_{self.collection_type}_{self.gws_domain}.json"
        self.cli_output_filename = f"_stats_cli_output_{self.collection_timestamp}_{self.collection_type}_{self.gws_domain}.txt"
        
        # Stats for CSV output
        self.file_stats_dict = {} # Using a dict, will be converted to list later
        
        # Stats tracking
        self.stats = {
            'total_saved': 0, 
            'total_found': 0,
            'api_calls': 0,
            'retries': 0,
            'errors': 0
        }

        # Create output path if required
        if not os.path.exists(self.output_path):
            os.makedirs(self.output_path)
            
        # Service cache for threads - more efficient caching
        self._service_cache = threading.local()
        self._service_instance = None  # Class-level cache for same credentials
            
        if self.verbosity >= 2:
            self._queue_message(f"Initialized with {self.num_threads} threads, verbosity level {self.verbosity}", 'info')
            
        # Start time measurement
        self.start_time = time.time()
        
        # Initialize display tracking
        self._last_display_update = 0  # Initialize display throttling
        self._previously_displayed_apps = set() # Track apps displayed in the last update
        
        # Initialize progress tracking for large collections
        self.app_activities = {}
        self.app_status = {}  # Track status: 'downloading', 'done'
        self.app_downloaded = {}  # Track downloaded counts for progress
        
        # For update mode, load previous stats for initial_collection_time
        self.previous_initial_times = {}
        if self.update:
            # Try to find the previous stats file in the original directory being updated
            # (not the parent of the new output_path)
            prev_dir = os.path.dirname(os.path.abspath(self.original_update_path.rstrip('/\\')))
            prev_stats = None
            for fname in os.listdir(prev_dir):
                if fname.startswith('_stats_') and fname.endswith('.csv'):
                    prev_stats = os.path.join(prev_dir, fname)
                    break
            if prev_stats and os.path.exists(prev_stats):
                try:
                    with open(prev_stats, 'r', newline='') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            key = (row['application'], os.path.basename(row['file_path']))
                            self.previous_initial_times[key] = row.get('initial_collection_time', row.get('collection_time', self.collection_timestamp))
                    if self.verbosity >= 2:
                        self._queue_message(f"Loaded previous stats from {prev_stats}", 'info')
                except Exception as e:
                    self._queue_message(f"Could not read previous stats file: {e}", 'warning')
            else:
                if self.verbosity >= 2:
                    self._queue_message(f"No previous stats file found in {prev_dir}", 'warning')

    def _queue_message(self, message, level='info'):
        """
        Display messages immediately with proper timestamps during download and log to buffer.
        Thread-safe with atomic print and buffer operations.
        """
        # Display immediately with ISO8601 UTC timestamp
        timestamp = datetime.now(tz=tz.tzutc()).strftime('%Y-%m-%dT%H%M%SZ')
        
        output_line = None
        if level == 'error':
            output_line = f"[{timestamp}] | {'ERROR':<12} | {'ERROR':<25} | {message}"
        elif level == 'warning':
            output_line = f"[{timestamp}] | {'WARNING':<12} | {'WARNING':<25} | {message}"
        elif level == 'info':
            if self.verbosity >= 2:
                output_line = f"[{timestamp}] | {'INFO':<12} | {'INFO':<25} | {message}"
        elif level == 'debug':
            if self.verbosity >= 3:
                output_line = f"[{timestamp}] | {'DEBUG':<12} | {'DEBUG':<25} | {message}"
        
        # Thread-safe: atomic print and buffer operations
        if output_line:
            with self.log_lock:
                print(output_line)
                self.cli_output_buffer.append(output_line)

    def _display_progress_update(self, app_name, count, status='DOWNLOADING'):
        """
        Display intermediate progress updates for apps that are downloading.
        Thread-safe with atomic print and buffer operations.
        """
        timestamp = datetime.now(tz=tz.tzutc()).strftime('%Y-%m-%dT%H%M%SZ')
        output_line = f"[{timestamp}] | {status:<12} | {app_name:<25} | {count} activities"
        
        # Thread-safe: atomic print and buffer operations
        with self.log_lock:
            print(output_line)
            self.cli_output_buffer.append(output_line)

    @staticmethod
    def get_application_list():
        """ 
        Returns a list of valid applicationName parameters for the activities.list() API method 
        from the API discovery endpoint.
        
        Note: This returns all applications listed by the API discovery endpoint, including
        those that may not be fully documented. The script will attempt to fetch logs for all
        of them, and the API will return appropriate errors for applications that aren't
        supported or available for the specific Google Workspace account/edition.
        """
        try:
            r = requests.get('https://admin.googleapis.com/$discovery/rest?version=reports_v1', timeout=10)
            r.raise_for_status()
            all_apps = r.json()['resources']['activities']['methods']['list']['parameters']['applicationName']['enum']
            # Return all applications - let the API tell us which ones are actually supported
            return all_apps
        except (requests.RequestException, KeyError, json.JSONDecodeError) as e:
            # Use print for static method since we don't have access to structured_log
            print(f"ERROR: Error fetching application list: {e}", file=sys.stderr)
            # Return default list as fallback
            return Google.DEFAULT_APPLICATIONS

    @staticmethod
    def _check_recent_date(log_file_path, sample_size=1000):
        """
        Opens an existing log file to find the datetime of the most recent record.
        Optimized to sample the last N lines for performance with large files.
        """
        return_date = None
        
        if not os.path.exists(log_file_path):
            return return_date
            
        try:
            # Fast approach for large files - read last N lines
            file_size = os.path.getsize(log_file_path)
            
            # For small files, just read the whole file
            if file_size < 1024 * 1024:  # Less than 1MB
                with open(log_file_path, 'r') as f:
                    lines = f.readlines()
            else:
                # For large files, read the last chunk
                chunk_size = min(file_size, 1024 * 1024)  # 1MB or file size
                with open(log_file_path, 'r') as f:
                    f.seek(max(0, file_size - chunk_size))
                    # Skip partial line
                    if file_size > chunk_size:
                        f.readline()
                    lines = f.readlines()
                    
                # Limit to last N lines for processing
                lines = lines[-sample_size:] if len(lines) > sample_size else lines
            
            # Process the lines to find the most recent date
            for line in lines:
                try:
                    json_obj = json.loads(line)
                    line_datetime = dateparser.parse(json_obj['id']['time'])
                    if not return_date or return_date < line_datetime:
                        return_date = line_datetime
                except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
                    continue
                    
        except Exception as e:
            # Use print for static method since we don't have access to structured_log
            print(f"WARNING: Error reading date from log file {log_file_path}: {e}", file=sys.stderr)
            
        return return_date

    def google_session(self):
        """
        Establish connection to Google Workspace.
        Using optimized caching to ensure thread safety and performance.
        Supports both Service Account and OAuth authentication.
        """
        # Check if we already have a service in thread-local storage
        if hasattr(self._service_cache, 'service'):
            return self._service_cache.service
        
        # Check if we have a class-level cached service (for same credentials)
        if self._service_instance is not None:
            self._service_cache.service = self._service_instance
            return self._service_instance
            
        # Create new service for this thread
        try:
            if self.auth_method == 'oauth':
                # Use pre-initialized OAuth credentials
                if not self._credentials:
                    raise ValueError("OAuth credentials not initialized")
                credentials = self._credentials
            else:
                # Service Account authentication (original method)
                if not self.delegated_creds:
                    raise ValueError("delegated_creds is required for service account authentication")
                    
                SCOPES = ['https://www.googleapis.com/auth/admin.reports.audit.readonly']
                creds = service_account.Credentials.from_service_account_file(
                    self.creds_path, scopes=SCOPES)
                credentials = creds.with_subject(self.delegated_creds)

            service = build('admin', 'reports_v1', credentials=credentials)
            
            # Store in both thread-local and class-level cache
            self._service_cache.service = service
            self._service_instance = service
            
            if self.verbosity >= 3:
                self._queue_message(f"Thread {threading.current_thread().name} created new API session using {self.auth_method}", 'debug')
                    
            return service
            
        except Exception as e:
            self._queue_message(f"Failed to create Google API session: {e}", 'error')
            raise

    def _get_oauth_credentials(self, scopes):
        """
        Handle OAuth authentication flow (based on ALFA implementation)
        """
        creds = None
        
        if self.verbosity >= 2:
            self._queue_message(f"Looking for OAuth token at: {self.token_file}", 'debug')
            self._queue_message(f"Token file exists: {os.path.exists(self.token_file)}", 'debug')
        
        # Check if we have a saved token (ALFA approach)
        if os.path.exists(self.token_file):
            try:
                creds = Credentials.from_authorized_user_file(self.token_file)
                if self.verbosity >= 2:
                    self._queue_message(f"Loaded existing OAuth token from {self.token_file}", 'info')
            except Exception as e:
                # Check if it's the specific refresh_token missing error
                if "missing fields refresh_token" in str(e):
                    if self.verbosity >= 1:
                        self._queue_message(f"Token missing refresh_token field. This is normal if you've previously authorized this app. Authentication will still work.", 'warning')
                else:
                    if self.verbosity >= 1:
                        self._queue_message(f"Could not load existing token: {e}", 'warning')
                
                # Try loading token manually like ALFA might
                try:
                    with open(self.token_file, 'r') as f:
                        token_data = json.load(f)
                    # Create credentials from token data
                    creds = Credentials(
                        token=token_data.get('token'),
                        refresh_token=token_data.get('refresh_token'),
                        token_uri=token_data.get('token_uri'),
                        client_id=token_data.get('client_id'),
                        client_secret=token_data.get('client_secret'),
                        scopes=token_data.get('scopes')
                    )
                    if self.verbosity >= 2:
                        self._queue_message(f"Manually loaded OAuth token from {self.token_file}", 'info')
                except Exception as e2:
                    if self.verbosity >= 1:
                        self._queue_message(f"Could not manually load token: {e2}", 'warning')
                    creds = None
                
        # ALFA's approach: check validity and refresh if needed
        if not creds or not creds.valid:
            if not os.path.exists(self.creds_path):
                error_msg = f"""
[!] Missing OAuth credentials file: {self.creds_path}

[*] Please run OAuth initialization first:
   python gws-log-collector.py --init --creds-path {self.creds_path}

[+] This will:
   1. Set up OAuth authentication 
   2. Create the token file
   3. Enable access to all log types including Keep
"""
                raise ValueError(error_msg)
                
            # Try to refresh if we have refresh token (ALFA approach)
            if creds and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    if self.verbosity >= 2:
                        self._queue_message("Refreshed OAuth token", 'info')
                    # Save refreshed token
                    with open(self.token_file, 'w') as token:
                        token.write(creds.to_json())
                except Exception as e:
                    if self.verbosity >= 1:
                        self._queue_message(f"Token refresh failed: {e}", 'warning')
                    creds = None
            
            # If still no valid credentials, require re-init (don't auto-authenticate here)
            if not creds or not creds.valid:
                error_msg = f"""
[!] OAuth token not found or invalid: {self.token_file}

[*] Please run OAuth initialization first:
   python gws-log-collector.py --init --creds-path {self.creds_path}

[+] This will:
   1. Set up OAuth authentication 
   2. Create the token file
   3. Enable access to all log types including Keep
"""
                raise ValueError(error_msg)
        
        return creds

    def _api_call_with_retry(self, service_method, **kwargs):
        """
        Makes an API call with exponential backoff retry logic
        """
        # Update API call counter
        with self.stats_lock:
            self.stats['api_calls'] += 1
            
        retry_attempt = 0
        last_exception = None
        
        while retry_attempt < self.RETRY_MAX_ATTEMPTS:
            try:
                # Attempt the API call
                return service_method(**kwargs).execute()
            except HttpError as e:
                status_code = e.resp.status
                
                # Don't retry on client errors (except 429 rate limit)
                if 400 <= status_code < 500 and status_code != 429:
                    raise
                
                last_exception = e
                retry_attempt += 1
                
                # Update retry counter
                with self.stats_lock:
                    self.stats['retries'] += 1
                
                # Log the retry at appropriate verbosity
                if self.verbosity >= 2:
                    self._queue_message(f"API error ({status_code}), retry {retry_attempt}/{self.RETRY_MAX_ATTEMPTS}", 'warning')
                
                # If we've exhausted all retries, break out
                if retry_attempt >= self.RETRY_MAX_ATTEMPTS:
                    break
                    
                # Calculate backoff delay with jitter
                delay = min(
                    self.RETRY_INITIAL_DELAY * (self.RETRY_BACKOFF_FACTOR ** (retry_attempt - 1)),
                    self.RETRY_MAX_DELAY
                )
                # Add jitter (±20%)
                delay = delay * (0.8 + 0.4 * (time.time() % 1))
                
                time.sleep(delay)
            except Exception as e:
                # For other exceptions, retry with backoff
                last_exception = e
                retry_attempt += 1
                
                with self.stats_lock:
                    self.stats['retries'] += 1
                
                if self.verbosity >= 2:
                    self._queue_message(f"Unexpected error: {e}, retry {retry_attempt}/{self.RETRY_MAX_ATTEMPTS}", 'warning')
                
                if retry_attempt >= self.RETRY_MAX_ATTEMPTS:
                    break
                    
                delay = min(
                    self.RETRY_INITIAL_DELAY * (self.RETRY_BACKOFF_FACTOR ** (retry_attempt - 1)),
                    self.RETRY_MAX_DELAY
                )
                time.sleep(delay)
        
        # We've exhausted all retries and still failed
        with self.stats_lock:
            self.stats['errors'] += 1
            
        # Queue retry failure error for safe display by main thread
        if last_exception:
            error_str = str(last_exception)
            if "does not match the pattern" in error_str and "applicationName" in error_str:
                # Extract app name from error for cleaner message
                if '"' in error_str:
                    # Look for the value part: "applicationName" value "invalid_app_name"
                    parts = error_str.split('"')
                    if len(parts) >= 4:
                        app_name = parts[3]  # The actual app name value
                    else:
                        app_name = parts[1]  # Fallback
                    self._queue_message(f"Application '{app_name}' is not supported by Google Workspace API", 'error')
                else:
                    self._queue_message(f"Invalid application name specified", 'error')
            else:
                self._queue_message(f"API call failed after {self.RETRY_MAX_ATTEMPTS} retries: {last_exception}", 'error')
        else:
            self._queue_message(f"API call failed after {self.RETRY_MAX_ATTEMPTS} retries", 'error')
            
        # Re-raise the last exception
        if last_exception:
            raise last_exception
        else:
            raise Exception("API call failed after retries")

    def _calculate_file_stats(self, app_name, file_path, record_count, updated_record_count, original_update_path):
        """
        Calculate MD5 and SHA1 hashes for a file, and return stats dict including initial_collection_time, updated_record_count, and original_update_path
        """
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        try:
            # Check if file exists and has content
            if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        md5_hash.update(chunk)
                        sha1_hash.update(chunk)
                file_size = os.path.getsize(file_path)
                md5_digest = md5_hash.hexdigest()
                sha1_digest = sha1_hash.hexdigest()
            else:
                file_size = 0 if not os.path.exists(file_path) else os.path.getsize(file_path)
                md5_digest = "d41d8cd98f00b204e9800998ecf8427e"
                sha1_digest = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
            # Determine initial_collection_time
            if self.update:
                key = (app_name, os.path.basename(file_path))
                initial_collection_time = self.previous_initial_times.get(key, self.collection_timestamp)
            else:
                initial_collection_time = self.collection_timestamp
            return {
                'application': app_name,
                'file_path': file_path,
                'record_count': record_count,
                'updated_record_count': updated_record_count,
                'md5': md5_digest,
                'sha1': sha1_digest,
                'file_size': file_size,
                'collection_time': self.collection_timestamp,
                'initial_collection_time': initial_collection_time,
                'collection_type': self.collection_type,
                'original_update_path': original_update_path
            }
        except Exception as e:
            self._queue_message(f"Error calculating hash for {file_path}: {e}", 'error')
            return {
                'application': app_name,
                'file_path': file_path,
                'record_count': record_count,
                'updated_record_count': updated_record_count,
                'md5': 'ERROR',
                'sha1': 'ERROR',
                'file_size': 0,
                'collection_time': self.collection_timestamp,
                'initial_collection_time': self.collection_timestamp,
                'collection_type': self.collection_type,
                'original_update_path': original_update_path
            }
            
    def _write_stats_csv(self):
        """
        Write stats_{timestamp}.csv file with information about each log file
        Places the stats file in the collection directory.
        """
        try:
            # Place stats file directly in the collection directory
            csv_path = os.path.join(self.output_path, self.stats_filename)
            
            with open(csv_path, 'w', newline='') as csvfile:
                fieldnames = ['application', 'file_path', 'record_count', 'updated_record_count', 'file_size', 
                              'md5', 'sha1', 'collection_time', 'initial_collection_time', 'collection_type', 'original_update_path']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for stat in sorted(self.file_stats, key=lambda x: x['application']):
                    writer.writerow(stat)
            if self.verbosity >= 1:
                self._queue_message(f"Wrote stats file to {csv_path}", 'info')
        except Exception as e:
            self._queue_message(f"Error writing stats CSV: {e}", 'error')

    def _write_stats_json(self):
        """
        Write _stats_{timestamp}.json file with information about each log file.
        Places the stats file in the collection directory.
        """
        try:
            # Place stats file directly in the collection directory
            json_path = os.path.join(self.output_path, self.stats_json_filename)
            
            # Ensure self.file_stats is sorted by application for consistent output
            sorted_stats = sorted(self.file_stats, key=lambda x: x.get('application', ''))
            
            with open(json_path, 'w') as jsonfile:
                json.dump(sorted_stats, jsonfile, indent=4)
            
            if self.verbosity >= 1:
                self._queue_message(f"Wrote JSON stats file to {json_path}", 'info')
        except Exception as e:
            self._queue_message(f"Error writing JSON stats file: {e}", 'error')

    def _write_cli_output(self):
        """
        Write CLI output to text file - exact copy of terminal output.
        Places the CLI output file in the collection directory.
        """
        try:
            # Place CLI output file directly in the collection directory
            cli_output_path = os.path.join(self.output_path, self.cli_output_filename)
            
            with open(cli_output_path, 'w', encoding='utf-8') as cli_file:
                # Write all captured CLI output exactly as it appeared on terminal
                for line in self.cli_output_buffer:
                    cli_file.write(line + '\n')
            
            # No need to display completion message here - it's handled in main script
                
        except Exception as e:
            self._queue_message(f"Error writing CLI output file: {e}", 'error')

    def get_logs(self, from_date=None, to_date=None):
        """ 
        Collect all logs from specified applications using thread pool
        """
        # Start time for this operation
        operation_start = time.time()
        
        # Reset stats
        self.stats = {
            'total_saved': 0, 
            'total_found': 0,
            'api_calls': 0,
            'retries': 0,
            'errors': 0
        }
        
        # Initialize a dictionary to hold stats for each app.
        # This ensures all apps in self.app_list will have an entry.
        self.file_stats_dict = {}
        for app_name_init in self.app_list:
            output_file_init = f"{self.output_path}/{app_name_init}.json"
            # Pre-populate with a default/zero-count stat.
            # Hashes will be for a non-existent/empty file initially if it's not yet created.
            # record_count and updated_record_count are 0.
            # initial_collection_time will be correctly determined by _calculate_file_stats.
            self.file_stats_dict[app_name_init] = self._calculate_file_stats(
                app_name_init, 
                output_file_init, 
                0, # record_count
                0, # updated_record_count
                self.stats_original_update_path
            )
        
        # Log start of collection
        if self.verbosity >= 1:
            self._queue_message(f"Starting log collection for {len(self.app_list)} applications using {self.num_threads} threads", 'info')
            if self.update:
                self._queue_message(f"Running in update mode (mode: {self.update_mode}) - behavior depends on mode.", 'info')
        
        # Prepare task queue with all applications
        tasks = []
        skipped_apps = set() # Still needed to control which apps go into 'tasks'
        for app in self.app_list:
            output_file = f"{self.output_path}/{app}.json"
            app_from_date = from_date
            skip_app = False
            if self.update and self.update_mode == 'append':
                original_folder = getattr(self, 'original_update_path', None)
                if not original_folder: # Fallback if not set directly
                    original_folder = os.path.dirname(os.path.abspath(self.output_path.rstrip('/\\\\')))
                original_file = os.path.join(original_folder, f"{app}.json")
                if not os.path.exists(original_file) or os.path.getsize(original_file) == 0:
                    if self.verbosity >= 2:
                        self._queue_message(f"Skipping {app} (no original file or file is empty) in append mode", 'info')
                    skip_app = True
                    skipped_apps.add(app)
                    # For skipped apps, their entry in self.file_stats_dict remains the default one created above.
            
            if not skip_app:
                if self.verbosity >= 2:
                    self._queue_message(f"Checking most recent date for {app} (if applicable for update)...", 'info')
                
                # Special handling for apps requiring date ranges (like gmail)
                # For these apps, if no explicit dates are provided, use maximum 30-day range from now
                if app in self.APPS_REQUIRING_DATE_RANGE:
                    if from_date is None and to_date is None:
                        # Use maximum 30-day range from execution time
                        now = datetime.now(tz=tz.tzutc())
                        app_from_date = now - timedelta(days=30)
                        app_to_date = now
                        if self.verbosity >= 2:
                            self._queue_message(f"{app} requires date range: using maximum 30-day range from now ({app_from_date} to {app_to_date})", 'info')
                    else:
                        # Use provided dates (will be validated/adjusted in _prepare_date_params_for_app)
                        app_from_date = from_date
                        app_to_date = to_date
                else:
                    # For other apps, use standard logic
                    # For update modes, _check_recent_date on the *new* output_file (which would have been copied)
                    # or from_date if file is new or _check_recent_date fails.
                    app_from_date = self._check_recent_date(output_file) or from_date
                    app_to_date = to_date
                
                if self.verbosity >= 2 and app_from_date:
                    self._queue_message(f"Will only fetch {app} logs after {app_from_date}", 'info')
                if self.verbosity >= 2 and app_to_date:
                    self._queue_message(f"Will only fetch {app} logs before {app_to_date}", 'info')
                tasks.append((app, output_file, app_from_date, app_to_date))
        
        # Initialize activity tracking for ALFA-style output
        self.app_activities = {app: 0 for app in self.app_list}
        self.app_downloaded = {app: 0 for app in self.app_list}  # Initialize all apps
        self.apps_completed = 0
        self.apps_total = len(tasks)
        self.apps_in_progress = set()  # Track which apps are currently being processed
        self.apps_done = set()  # Track which apps are completed
        
        # Mark skipped apps as done immediately
        for skipped_app in skipped_apps:
            self.apps_done.add(skipped_app)
        

        
        # Show initial ALFA-style output
        if self.verbosity >= 1:
            # Reset display lines count for collection phase
            self._last_display_update = 0
            self._display_activity_status()
        
        # Create a thread pool
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            # Submit each app to the thread pool
            futures = {
                executor.submit(
                    self._get_activity_logs,
                    app_task, # Renamed to avoid clash with loop var 'app'
                    output_file_task, # Renamed
                    only_after_datetime_task, # Renamed
                    only_before_datetime_task # New parameter
                ): (app_task, output_file_task) for app_task, output_file_task, only_after_datetime_task, only_before_datetime_task in tasks
            }
            
            # Mark all submitted apps as in progress
            for app_task, output_file_task, only_after_datetime_task, only_before_datetime_task in tasks:
                self.apps_in_progress.add(app_task)
            
            # Update display to show in-progress status
            if self.verbosity >= 1:
                self._display_activity_status()
            
            # Process results as they complete
            for future in as_completed(futures):
                app_processed, output_file_processed = futures[future] # Get app_name and output_file for this future
                current_app_stats_dict_entry = {} # To hold the new stats for this app

                try:
                    # _get_activity_logs should return (new_records_written_this_run, records_fetched_from_api_this_run)
                    newly_written_for_app, fetched_from_api_for_app = future.result()
                    
                    # Update activity count for this app
                    self.app_activities[app_processed] = fetched_from_api_for_app
                    
                    actual_record_count_in_file = 0
                    try:
                        if os.path.exists(output_file_processed): # Check existence before opening
                            with open(output_file_processed, 'r') as f_recount:
                                actual_record_count_in_file = sum(1 for line in f_recount if line.strip())
                    except Exception as e_recount:
                        if self.verbosity >= 1: 
                            self._queue_message(f"Could not recount lines for {output_file_processed}: {e_recount}", 'warning')
                        # Keep actual_record_count_in_file as 0 or last known good if partial read? For now, 0.
                    
                    with self.stats_lock:
                        self.stats['total_saved'] += newly_written_for_app
                        self.stats['total_found'] += fetched_from_api_for_app
                    
                    current_app_stats_dict_entry = self._calculate_file_stats(
                        app_processed, 
                        output_file_processed, 
                        actual_record_count_in_file, # record_count in file
                        newly_written_for_app,       # updated_record_count (new this run)
                        self.stats_original_update_path
                    )
                    
                    if self.verbosity >= 2:
                        self._queue_message(f"Completed {app_processed}: saved {newly_written_for_app} of {fetched_from_api_for_app} API entries. File has {actual_record_count_in_file} records.", 'info')
                            
                except Exception as e_future:
                    # Queue error for safe display
                    if self.verbosity >= 1: 
                        self._queue_message(f"Error processing {app_processed}: {e_future}", 'error')
                    with self.stats_lock:
                        self.stats['errors'] += 1
                        
                    # Create an error stat entry. `output_file_processed` is known.
                    current_app_stats_dict_entry = self._calculate_file_stats(
                        app_processed, 
                        output_file_processed, 
                        0, # record_count on error (or try to get from existing pre-populated if smarter)
                        0, # updated_record_count on error
                        self.stats_original_update_path
                    )
                
                # Update the dictionary entry for this app
                if app_processed in self.file_stats_dict:
                    self.file_stats_dict[app_processed] = current_app_stats_dict_entry
                else: 
                    # This case should ideally not be reached if pre-population covers all self.app_list
                    if self.verbosity >= 0: 
                        self._queue_message(f"CRITICAL: App {app_processed} from future not found in pre-populated stats dictionary! Adding it now.", 'error')
                    self.file_stats_dict[app_processed] = current_app_stats_dict_entry # Add if somehow missing
                    
                # Update progress tracking
                self.apps_in_progress.discard(app_processed)  # Remove from in-progress
                self.apps_done.add(app_processed)  # Add to completed
                self.apps_completed += 1
                
                # Update progress display (which will also process any queued messages)
                if self.verbosity >= 1:
                    self._display_activity_status()
            
        # Final display and process any remaining queued messages
        if self.verbosity >= 1:
            self._display_activity_status(final=True)
        
        # Convert the dictionary of stats to a list for CSV writing and other uses
        self.file_stats = list(self.file_stats_dict.values())
        
        # Write stats CSV file with timestamp (after all apps are ensured present and updated)
        self._write_stats_csv() # _write_stats_csv sorts by application before writing
        
        # Write stats JSON file with timestamp (after all apps are ensured present and updated)
        self._write_stats_json() # _write_stats_json sorts by application before writing
        
        # Note: CLI output file is written after execution summary in main script
        
        # Calculate elapsed time
        elapsed = time.time() - operation_start
        
        # Final summary - always show this regardless of verbosity
        self._queue_message(f"COMPLETED IN {elapsed:.2f}s: Saved {self.stats['total_saved']} of {self.stats['total_found']} records from API calls this run.", 'info')
        
        if self.verbosity >= 2:
            self._queue_message(f"API Calls: {self.stats['api_calls']}, Retries: {self.stats['retries']}, Errors: {self.stats['errors']}", 'info')
        
        return self.stats

    def _display_activity_status(self, final=False):
        """
        Display ALFA-style activity status with progress information
        """
        # Safety check to prevent infinite display loops
        if hasattr(self, '_display_in_progress') and self._display_in_progress:
            return
        self._display_in_progress = True
        
        try:
            # New approach: Print a simple, single line for each update to avoid overwriting.
            
            # Check for completed apps since last display update
            newly_completed_apps = self.apps_done - self._previously_displayed_apps
            
            for app in sorted(list(newly_completed_apps)):
                downloaded_count = self.app_downloaded.get(app, 0)
                error_for_app = self.app_status.get(app) == 'error'
                status = "DONE" if not error_for_app else "ERROR"
                
                # Use ISO8601 UTC format consistent with stats files
                timestamp = datetime.now(tz=tz.tzutc()).strftime('%Y-%m-%dT%H%M%SZ')
                output_line = f"[{timestamp}] | {status:<12} | {app:<25} | {downloaded_count} activities"
                
                # Thread-safe: atomic print and buffer operations
                with self.log_lock:
                    print(output_line)
                    self.cli_output_buffer.append(output_line)
                self._previously_displayed_apps.add(app)

            # Show overall progress only when meaningful and avoid duplicates
            show_progress = False
            
            if final and self.apps_completed > 0:
                # Show final progress only if we haven't just shown it
                show_progress = (time.time() - self._last_display_update > 1)
            elif not final and self.apps_completed > 0:
                # Show periodic progress only if enough time has passed AND we have some progress
                show_progress = (time.time() - self._last_display_update > 2)
            
            if show_progress and self.apps_total > 0:
                progress_pct = (self.apps_completed / self.apps_total) * 100
                elapsed = time.time() - self.start_time
                
                error_count = self.stats['errors']
                error_suffix = f" | {error_count} errors" if error_count > 0 else ""

                # Use consistent timestamp format for progress lines too
                timestamp = datetime.now(tz=tz.tzutc()).strftime('%Y-%m-%dT%H%M%SZ')
                progress_line = f"[{timestamp}] | {'PROGRESS':<12} | {'Overall Progress':<25} | {self.apps_completed}/{self.apps_total} apps done ({progress_pct:.0f}%){error_suffix} [Elapsed: {elapsed:.1f}s]"
                
                # Thread-safe: atomic print and buffer operations
                with self.log_lock:
                    print(progress_line)
                    self.cli_output_buffer.append(progress_line)
                self._last_display_update = time.time()

            if final:
                pass  # No extra spacing needed
            
        finally:
            self._display_in_progress = False

    def _write_entries_to_file(self, entries, output_file, mode='a'):
        """Helper method to write entries to file with proper formatting"""
        try:
            with open(output_file, mode) as f:
                for entry in entries:
                    f.write(entry.rstrip() + '\n')
            return True
        except Exception as e:
            self._queue_message(f"Error writing to {output_file}: {e}", 'error')
            return False
    
    def _prepare_date_params_for_app(self, application_name, only_after_datetime, only_before_datetime):
        """
        Prepare startTime and endTime parameters for API calls.
        Special handling for applications that require both dates (e.g., gmail).
        Returns (start_time_str, end_time_str) tuple or (None, None) if not needed.
        """
        # Check if this application requires both startTime and endTime
        requires_both = application_name in self.APPS_REQUIRING_DATE_RANGE
        
        if not requires_both:
            # For other apps, use dates as provided
            start_time_str = only_after_datetime.isoformat() if only_after_datetime else None
            end_time_str = only_before_datetime.isoformat() if only_before_datetime else None
            return (start_time_str, end_time_str)
        
        # For apps requiring both dates (like gmail)
        now = datetime.now(tz=tz.tzutc())
        
        # If we have both dates, use them (but ensure range <= 30 days)
        if only_after_datetime and only_before_datetime:
            # Check if range exceeds 30 days
            delta = only_before_datetime - only_after_datetime
            if delta.days > 30:
                # Adjust endTime to be 30 days after startTime
                if self.verbosity >= 2:
                    self._queue_message(f"Date range for {application_name} exceeds 30 days, adjusting endTime to 30 days after startTime", 'warning')
                adjusted_end = only_after_datetime + timedelta(days=30)
                # Don't exceed current time
                if adjusted_end > now:
                    adjusted_end = now
                return (only_after_datetime.isoformat(), adjusted_end.isoformat())
            return (only_after_datetime.isoformat(), only_before_datetime.isoformat())
        
        # If we only have startTime, set endTime to 30 days later (or now, whichever is earlier)
        if only_after_datetime:
            end_time = only_after_datetime + timedelta(days=30)
            if end_time > now:
                end_time = now
            if self.verbosity >= 2:
                self._queue_message(f"{application_name} requires both dates, setting endTime to 30 days after startTime (or now)", 'info')
            return (only_after_datetime.isoformat(), end_time.isoformat())
        
        # If we only have endTime, set startTime to 30 days earlier
        if only_before_datetime:
            start_time = only_before_datetime - timedelta(days=30)
            if self.verbosity >= 2:
                self._queue_message(f"{application_name} requires both dates, setting startTime to 30 days before endTime", 'info')
            return (start_time.isoformat(), only_before_datetime.isoformat())
        
        # If we have neither, use maximum 30-day range from current execution time
        if self.verbosity >= 2:
            self._queue_message(f"{application_name} requires both dates, using maximum 30-day range from execution time: {now - timedelta(days=30)} to {now}", 'info')
        end_time = now
        start_time = now - timedelta(days=30)
        return (start_time.isoformat(), end_time.isoformat())

    def _get_activity_logs(self, application_name, output_file, only_after_datetime=None, only_before_datetime=None):
        """ Collect activity logs from the specified application with pagination support and incremental writing """
        if self.verbosity >= 2:
            self._queue_message(f"Starting collection for {application_name}...", 'info')
        
        # Initialize progress tracking (totals should already be set from upfront counting)
        if application_name not in self.app_downloaded:
            self.app_downloaded[application_name] = 0
        self.app_status[application_name] = 'downloading'
            
        service = self.google_session()
        total_activities = 0
        output_count = 0
        page_token = None
        page_count = 0
        write_count = 0  # Track records written for incremental writing
        
        if self.update and os.path.exists(output_file):
            # Deduplication mode (for all logs)
            existing_entries = set()
            existing_lines = []
            try:
                with open(output_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            entry_id_dict = entry.get('id', {})
                            entry_id = f"{entry_id_dict.get('time', '')}-{entry_id_dict.get('uniqueQualifier', '')}"
                            existing_entries.add(entry_id)
                            existing_lines.append(line)
                        except Exception as e:
                            if self.verbosity >= 3:
                                self._queue_message(f"Error parsing existing entry for deduplication: {e}", 'warning')
                if self.verbosity >= 2:
                    self._queue_message(f"Loaded {len(existing_entries)} existing entries for deduplication in {application_name}", 'info')
            except Exception as e:
                self._queue_message(f"Error reading existing file for deduplication: {e}", 'error')
                existing_entries = set()
                existing_lines = []
            new_entries = []
            try:
                while True:
                    page_count += 1
                    if self.verbosity >= 3:
                        self._queue_message(f"Fetching page {page_count} for {application_name}...", 'debug')
                    try:
                        # Build API call parameters
                        api_params = {
                            'userKey': 'all',
                            'applicationName': application_name,
                            'maxResults': self.max_results,
                            'pageToken': page_token
                        }
                        
                        # Prepare date parameters (with special handling for apps requiring both dates)
                        start_time_str, end_time_str = self._prepare_date_params_for_app(
                            application_name, only_after_datetime, only_before_datetime
                        )
                        
                        # Add date filtering parameters
                        if start_time_str:
                            api_params['startTime'] = start_time_str
                            if self.verbosity >= 2:
                                self._queue_message(f"Using API date filter for {application_name}: startTime={start_time_str}", 'info')
                        
                        if end_time_str:
                            api_params['endTime'] = end_time_str
                            if self.verbosity >= 2:
                                self._queue_message(f"Using API date filter for {application_name}: endTime={end_time_str}", 'info')
                        
                        results = self._api_call_with_retry(
                            service.activities().list,
                            **api_params
                        )
                    except Exception as e:
                        error_str = str(e)
                        if "does not match the pattern" in error_str:
                            # Queue unsupported app error for safe display
                            error_msg = f"Application '{application_name}' not supported by API or not available for this Google Workspace account/edition"
                            self._queue_message(error_msg, 'error')
                        else:
                            # Queue API error for safe display
                            self._queue_message(f"Failed to fetch logs for {application_name}: {e}", 'error')
                        with self.stats_lock:
                            self.stats['errors'] += 1
                        return 0, len(existing_entries)
                    activities = results.get('items', [])
                    page_activities = len(activities)
                    total_activities += page_activities
                    
                    page_token = results.get('nextPageToken')
                    if self.verbosity >= 3:
                        self._queue_message(f"{application_name}: Page {page_count} has {page_activities} activities, next token: {page_token}", 'debug')
                    if activities:
                        for entry in activities[::-1]:
                            # Only new records within the specified date range
                            try:
                                entry_datetime = dateparser.parse(entry['id']['time'])
                                
                                # Check if entry is after the start date
                                if only_after_datetime and entry_datetime <= only_after_datetime:
                                    continue
                                
                                # Check if entry is before the end date
                                if only_before_datetime and entry_datetime >= only_before_datetime:
                                    continue
                                    
                            except (KeyError, ValueError, TypeError) as e:
                                if self.verbosity >= 3:
                                    self._queue_message(f"Invalid date in entry: {e}", 'warning')
                                continue
                            try:
                                entry_id_dict = entry.get('id', {})
                                entry_id = f"{entry_id_dict.get('time', '')}-{entry_id_dict.get('uniqueQualifier', '')}"
                            except Exception as e:
                                if self.verbosity >= 3:
                                    self._queue_message(f"Error building entry_id: {e}", 'warning')
                                continue
                            if entry_id in existing_entries:
                                if self.verbosity >= 3:
                                    self._queue_message(f"Skipping duplicate entry: {entry_id}", 'debug')
                                continue
                            existing_entries.add(entry_id)
                            json_formatted_str = json.dumps(entry, separators=(',', ':'))
                            new_entries.append(json_formatted_str)
                            output_count += 1
                    if not page_token:
                        break
                # Write output depending on update_mode
                if self.update_mode == 'diff':
                    # Only write new entries
                    with open(output_file, 'w') as f:
                        for line in new_entries:
                            f.write(line + '\n')
                    if self.verbosity >= 2:
                        self._queue_message(f"Wrote {len(new_entries)} new entries to {output_file} (diff mode)", 'info')
                    total_lines = len(new_entries)
                else:
                    # Default: append mode (write all unique entries)
                    with open(output_file, 'w') as f:
                        # Write existing lines (may need rstrip)
                        for line in existing_lines:
                            f.write(line.rstrip() + '\n')
                        # Write new entries (already clean JSON strings)
                        for line in new_entries:
                            f.write(line + '\n')
                    if self.verbosity >= 2:
                        self._queue_message(f"Wrote {len(new_entries)} new entries to {output_file} with deduplication. Total unique: {len(existing_lines) + len(new_entries)}", 'info')
                    # After writing, recount the lines for record_count
                    try:
                        with open(output_file, 'r') as f:
                            total_lines = sum(1 for _ in f if _.strip())
                    except Exception:
                        total_lines = 0
            except Exception as e:
                # Queue error for safe display
                self._queue_message(f"Error processing file {output_file} for {application_name}: {e}", 'error')
                with self.stats_lock:
                    self.stats['errors'] += 1
                total_lines = len(existing_entries) + len(new_entries)
            
            # Update progress tracking variables before returning (needed for correct display)
            self.app_status[application_name] = 'done'
            self.app_activities[application_name] = output_count  # New records found
            self.app_downloaded[application_name] = output_count  # New records written
            
            # Return new records added, and total records in file
            return output_count, total_activities
        else:
            # Normal logic for initial collection with incremental writing
            written_entries = []  # Track all entries for final write
                
            try:
                while True:
                    page_count += 1
                    if self.verbosity >= 3:
                        self._queue_message(f"Fetching page {page_count} for {application_name}...", 'debug')
                    try:
                        # Build API call parameters
                        api_params = {
                            'userKey': 'all',
                            'applicationName': application_name,
                            'maxResults': self.max_results,
                            'pageToken': page_token
                        }
                        
                        # Prepare date parameters (with special handling for apps requiring both dates)
                        start_time_str, end_time_str = self._prepare_date_params_for_app(
                            application_name, only_after_datetime, only_before_datetime
                        )
                        
                        # Add date filtering parameters
                        if start_time_str:
                            api_params['startTime'] = start_time_str
                            if self.verbosity >= 2:
                                self._queue_message(f"Using API date filter for {application_name}: startTime={start_time_str}", 'info')
                        
                        if end_time_str:
                            api_params['endTime'] = end_time_str
                            if self.verbosity >= 2:
                                self._queue_message(f"Using API date filter for {application_name}: endTime={end_time_str}", 'info')
                        
                        results = self._api_call_with_retry(
                            service.activities().list,
                            **api_params
                        )
                    except Exception as e:
                        error_str = str(e)
                        if "does not match the pattern" in error_str:
                            # Queue unsupported app error for safe display
                            error_msg = f"Application '{application_name}' not supported by API or not available for this Google Workspace account/edition"
                            self._queue_message(error_msg, 'error')
                        else:
                            # Queue API error for safe display
                            self._queue_message(f"Failed to fetch logs for {application_name}: {e}", 'error')
                        with self.stats_lock:
                            self.stats['errors'] += 1
                        # Update status and return
                        self.app_status[application_name] = 'done'
                        self.app_activities[application_name] = output_count
                        return 0, total_activities
                        
                    activities = results.get('items', [])
                    page_activities = len(activities)
                    total_activities += page_activities
                    
                    page_token = results.get('nextPageToken')
                    if self.verbosity >= 3:
                        self._queue_message(f"{application_name}: Page {page_count} has {page_activities} activities, next token: {page_token}", 'debug')
                            
                    if activities:
                        for entry in activities[::-1]:
                            # Local date filtering as safety net (API should handle most filtering)
                            try:
                                entry_datetime = dateparser.parse(entry['id']['time'])
                                
                                # Check if entry is after the start date
                                if only_after_datetime and entry_datetime <= only_after_datetime:
                                    # This should be rare with API filtering
                                    if self.verbosity >= 3:
                                        self._queue_message(f"Skipping old entry locally: {entry['id']['time']}", 'debug')
                                    continue
                                
                                # Check if entry is before the end date
                                if only_before_datetime and entry_datetime >= only_before_datetime:
                                    if self.verbosity >= 3:
                                        self._queue_message(f"Skipping future entry locally: {entry['id']['time']}", 'debug')
                                    continue
                                    
                            except (KeyError, ValueError, TypeError) as e:
                                if self.verbosity >= 3:
                                    self._queue_message(f"Invalid date in entry: {e}", 'warning')
                                continue
                            json_formatted_str = json.dumps(entry, separators=(',', ':'))
                            output_count += 1
                            write_count += 1
                            
                            # Handle incremental writing
                            if self.write_batch_size > 0:
                                # Add to buffer for incremental writing
                                written_entries.append(json_formatted_str)
                                
                                # Write in batches when we reach write_batch_size
                                if write_count >= self.write_batch_size:
                                    # Write entries and clear buffer to free memory
                                    write_mode = 'w' if output_count == len(written_entries) else 'a'
                                    if self._write_entries_to_file(written_entries, output_file, write_mode):
                                        if self.verbosity >= 2:
                                            self._queue_message(f"Incremental write: {len(written_entries)} records written to {application_name}", 'info')
                                        
                                        # Update progress tracking only when batch is written to disk
                                        self.app_downloaded[application_name] = output_count
                                        self.app_activities[application_name] = output_count
                                        
                                        # Show intermediate progress for downloading
                                        if self.verbosity >= 1:
                                            self._display_progress_update(application_name, output_count, 'DOWNLOADING')
                                        
                                        # Update display only when batch is written to disk
                                        if self.verbosity >= 1:
                                            current_time = time.time()
                                            # Only update display if enough time has passed (minimum 0.5 seconds between updates)
                                            if current_time - self._last_display_update >= 0.5:
                                                self._display_activity_status()
                                                self._last_display_update = current_time
                                        
                                        # Clear buffer to free memory
                                        written_entries.clear()
                                        write_count = 0
                                    else:
                                        self.app_status[application_name] = 'done'
                                        return output_count, total_activities
                            else:
                                # Traditional mode: keep all entries in memory and update progress periodically
                                written_entries.append(json_formatted_str)
                                
                                # Update progress tracking and display every 1000 records for non-batch mode
                                if output_count % 1000 == 0:
                                    self.app_downloaded[application_name] = output_count
                                    self.app_activities[application_name] = output_count
                                    
                                    # Show intermediate progress for downloading
                                    if self.verbosity >= 1:
                                        self._display_progress_update(application_name, output_count, 'DOWNLOADING')
                                    
                                    if self.verbosity >= 1:
                                        current_time = time.time()
                                        # Only update display if enough time has passed (minimum 0.5 seconds between updates)
                                        if current_time - self._last_display_update >= 0.5:
                                            self._display_activity_status()
                                            self._last_display_update = current_time
                                
                    if not page_token:
                        break
                        
            except Exception as e:
                # Queue error for safe display
                self._queue_message(f"Error during collection for {application_name}: {e}", 'error')
                with self.stats_lock:
                    self.stats['errors'] += 1
                    
            # Final write of remaining entries (create file even if empty)
            if self.write_batch_size > 0:
                # Incremental mode: write any remaining entries and ensure file exists
                if written_entries:
                    # Append remaining entries
                    if not self._write_entries_to_file(written_entries, output_file, 'a'):
                        with self.stats_lock:
                            self.stats['errors'] += 1
                elif output_count == 0:
                    # No entries at all, create empty file
                    if not self._write_entries_to_file([], output_file, 'w'):
                        with self.stats_lock:
                            self.stats['errors'] += 1
            else:
                # Traditional mode: write all entries at once
                if not self._write_entries_to_file(written_entries, output_file, 'w'):
                    with self.stats_lock:
                        self.stats['errors'] += 1
                    
            # Update final status and ensure final progress is recorded
            self.app_status[application_name] = 'done'
            self.app_activities[application_name] = output_count
            self.app_downloaded[application_name] = output_count
            
            # Final display update to show completion
            if self.verbosity >= 1:
                self._display_activity_status()
            
            return output_count, total_activities

    def print_execution_summary(self):
        """
        Print a summary of the execution statistics and timing
        """
        # Calculate total execution time
        total_execution_time = time.time() - self.start_time
        
        # Format time nicely
        if total_execution_time < 60:
            time_str = f"{total_execution_time:.2f} seconds"
        elif total_execution_time < 3600:
            minutes = int(total_execution_time // 60)
            seconds = total_execution_time % 60
            time_str = f"{minutes} minutes, {seconds:.2f} seconds"
        else:
            hours = int(total_execution_time // 3600)
            minutes = int((total_execution_time % 3600) // 60)
            seconds = total_execution_time % 60
            time_str = f"{hours} hours, {minutes} minutes, {seconds:.2f} seconds"
            
        # Print summary and capture to CLI buffer
        summary_lines = [
            "",
            "="*80,
            "EXECUTION SUMMARY",
            "="*80,
            f"Total execution time: {time_str}",
            f"Google Workspace Domain: {self.gws_domain}",
            f"Applications processed: {len(self.app_list)}",
            f"Records found: {self.stats['total_found']}",
            f"Records saved: {self.stats['total_saved']}",
            f"Collection type: {self.collection_type.upper()}",
            f"Collection folder: {os.path.abspath(self.output_path)}"
        ]
        
        for line in summary_lines:
            print(line)
            # Add all lines to CLI buffer including empty lines for proper formatting
            self.cli_output_buffer.append(line)
        
        # Stats file information - files are now in the collection directory
        stats_csv_path = os.path.join(self.output_path, self.stats_filename)
        stats_json_path = os.path.join(self.output_path, self.stats_json_filename)
        cli_output_path = os.path.join(self.output_path, self.cli_output_filename)
        
        additional_lines = []
        
        if os.path.exists(stats_csv_path):
            additional_lines.append(f"Stats file (CSV): {stats_csv_path}")
        
        # JSON Stats file information
        if os.path.exists(stats_json_path):
            additional_lines.append(f"Stats file (JSON): {stats_json_path}")
        
        # CLI Output file information - always show path even if file doesn't exist yet
        additional_lines.append(f"CLI Output file: {cli_output_path}")
            
        if self.stats['total_found'] > 0:
            # Calculate throughput
            records_per_second = self.stats['total_found'] / total_execution_time
            additional_lines.append(f"Throughput: {records_per_second:.2f} records/second")
            
        # Always show API statistics
        additional_lines.extend([
            f"API Calls Made: {self.stats['api_calls']}",
            f"Retries: {self.stats['retries']}",
            f"Errors: {self.stats['errors']}",
            "="*80
        ])
        
        # Print and capture additional summary lines
        for line in additional_lines:
            print(line)
            self.cli_output_buffer.append(line)


def handle_oauth_init(args):
    """
    Handle OAuth initialization similar to ALFA's approach
    """
    # Default credentials path for OAuth  
    creds_path = os.path.abspath(args.creds_path or 'oauth_credentials.json')
    token_path = os.path.abspath(args.token_file or 'token.json')
    
    print("="*80)
    print("OAUTH INITIALIZATION")
    print("="*80)
    
    # Check if credentials file exists
    if not os.path.exists(creds_path):
        print(f"\n[!] Missing OAuth credentials file: {creds_path}")
        print("\n[*] How to create OAuth credentials:")
        print("1. Go to https://console.cloud.google.com/apis/credentials")
        print("2. Create a new project or select existing one")
        print("3. Click 'Create Credentials' → 'OAuth client ID'")
        print("4. Choose 'Desktop application' as application type")
        print("5. Download the JSON file and save it as:", creds_path)
        print("\n[*] Required API:")
        print("   Make sure 'Admin SDK API' is enabled in your project")
        print("   https://console.cloud.google.com/apis/library/admin.googleapis.com")
        return False
    
    print(f"[+] Found OAuth credentials file: {creds_path}")
    
    # Check if token already exists
    if os.path.exists(token_path):
        print(f"[!] Existing token found: {token_path}")
        
        # Check if existing token has refresh_token
        try:
            with open(token_path, 'r') as f:
                token_data = json.load(f)
            if 'refresh_token' not in token_data:
                print("[!] Existing token is missing refresh_token - will re-authenticate")
                choice = 'y'
            else:
                choice = input("Do you want to re-authenticate? [y/N]: ").strip().lower()
        except Exception:
            print("[!] Existing token is corrupted - will re-authenticate") 
            choice = 'y'
            
        if choice not in ['y', 'yes']:
            print("[+] Using existing token")
            return True
        else:
            os.remove(token_path)
            print("[*] Deleted existing token")
    
    # Perform OAuth flow
    print(f"\n[*] Starting OAuth authentication...")
    print(f"[*] Browser will open for Google authentication")
    print(f"[*] Using callback port: {args.oauth_port}")
    print(f"\n[+] IMPORTANT: To ensure refresh token is included:")
    print(f"   1. If you've previously authorized this app, you may need to revoke access first")
    print(f"   2. Visit: https://myaccount.google.com/permissions") 
    print(f"   3. Find and remove this application if it exists")
    print(f"   4. The OAuth flow will force consent to ensure refresh token is generated")
    print(f"\n[*] Starting OAuth flow...")
    
    try:
        # Initialize OAuth flow
        SCOPES = ['https://www.googleapis.com/auth/admin.reports.audit.readonly']
        
        flow = InstalledAppFlow.from_client_secrets_file(creds_path, SCOPES)
        
        # Use ALFA's approach - simple OAuth flow with access_type=offline to ensure refresh_token
        creds = flow.run_local_server(
            port=args.oauth_port,
            access_type='offline',
            prompt='consent'
        )
        
        # Check if we got valid credentials (ALFA approach)
        if not creds or not creds.valid:
            print(f"\n[!] WARNING: Invalid credentials received!")
            return False
        
        # Save the credentials
        with open(token_path, 'w') as token:
            token.write(creds.to_json())
            
        print(f"[+] OAuth authentication successful!")
        print(f"[*] Token saved to: {token_path}")
        print(f"\n[+] You can now use OAuth authentication:")
        print(f"   python gws-log-collector.py --auth-method oauth --creds=\"{creds_path}\" --gws-domain YOUR_DOMAIN")
        
        return True
        
    except Exception as e:
        print(f"[!] OAuth authentication failed: {e}")
        return False


# Global CLI output buffer for pre-initialization logging
_global_cli_buffer = []

def structured_log(message, level='INFO'):
    """
    Create structured log output consistent with _queue_message format
    """
    timestamp = datetime.now(tz=tz.tzutc()).strftime('%Y-%m-%dT%H%M%SZ')
    output_line = f"[{timestamp}] | {level:<12} | {level:<25} | {message}"
    print(output_line)
    
    # Add to global CLI output buffer
    _global_cli_buffer.append(output_line)

if __name__ == '__main__':

    # Record start time
    script_start_time = time.time()

    parser = argparse.ArgumentParser(description='This script will fetch Google Workspace logs.')

    # Main commands
    parser.add_argument('--init', required=False, action='store_true',
                        help="Initialize OAuth credentials (required once before using OAuth authentication)")
    
    # Authentication arguments
    parser.add_argument('--creds-path', required=False, help="Path to credentials file (.json). For service-account: service account JSON file. For oauth: OAuth client secrets JSON file.")
    parser.add_argument('--auth-method', required=False, choices=['service-account', 'oauth'], default='service-account',
                        help="Authentication method. 'service-account' for automated access (default), 'oauth' for interactive authentication (supports Keep logs and others)")
    parser.add_argument('--delegated-creds', required=False, help="Principal name for service account delegation (required for service-account method)")
    parser.add_argument('--gws-domain', required=False, help="Google Workspace domain (e.g. example.com)")
    
    # OAuth specific arguments
    parser.add_argument('--oauth-port', required=False, type=int, default=8089,
                        help="Port for OAuth callback server (default: 8089, only used with oauth method)")
    parser.add_argument('--token-file', required=False, default='token.json',
                        help="Path to store OAuth token file (default: token.json, only used with oauth method)")
    # Output path - now has default with timestamp
    parser.add_argument('--output-path', '-o', required=False, 
                        help="Folder to save downloaded logs. Default is 'collection_<gws-domain>_<collection_type>_<collection_timestamp>'")
    parser.add_argument('--apps', '-a', required=False, default='all', 
                        help="Comma separated list of applications whose logs will be downloaded. "
                         "Or 'all' to attempt to download all available logs (default)")
    parser.add_argument('--from-date', required=False, default=None,
                        type=lambda s: dateparser.parse(s).replace(tzinfo=tz.gettz('UTC')),
                        help="Only capture log entries from the specified date [yyyy-mm-dd format]. This flag is ignored if --update is set and existing files are already present.")
    parser.add_argument('--to-date', required=False, default=None,
                        type=lambda s: dateparser.parse(s).replace(tzinfo=tz.gettz('UTC')),
                        help="Only capture log entries up to the specified date [yyyy-mm-dd format]. Can be combined with --from-date for date range filtering.")
    # Update behaviour
    parser.add_argument('--update', '-u', required=False, 
                        help="Update an existing collection folder with new logs. Specify the folder to update.")
    parser.add_argument('--update-mode', required=False, choices=['append', 'diff'], default=None,
                        help="Update mode: 'append' (deduplicate and write all unique records) or 'diff' (write only new records found in this update). REQUIRED if --update is used.")
    # Add max_results parameter
    parser.add_argument('--max-results', required=False, type=int, default=1000,
                        help="Maximum number of results per API page (1-1000). Default is 1000.")
    # Add thread count parameter
    parser.add_argument('--threads', '-t', dest="num_threads", required=False, type=int, default=20,
                        help="Number of parallel threads to use for fetching logs. Default is 20.")
    # Add write batch size parameter
    parser.add_argument('--write-batch-size', required=False, type=int, default=100000,
                        help="Write log entries to disk every N events to reduce memory usage for large collections. Set to 0 to write only at the end. Default is 100000.")
    # Progress bar control
    parser.add_argument('--no-progress', required=False, action="store_true",
                        help="Disable progress bars")
    # Logging/output levels - modified for more granular control
    parser.add_argument('--quiet', '-q', required=False, action="store_true",
                        help="Minimal output (only errors and final summary)")
    parser.add_argument('--verbose', '-v', required=False, action="count", default=0,
                        help="Increase verbosity level (can be used multiple times, e.g. -vv)")

    args = parser.parse_args()

    # Handle init command
    if args.init:
        handle_oauth_init(args)
        sys.exit(0)

    # Validation for normal operation
    if not args.creds_path:
        parser.error("argument --creds-path is required")
    if not args.gws_domain:
        parser.error("argument --gws-domain is required")
    
    # Validation based on authentication method
    if args.auth_method == 'service-account' and not args.delegated_creds:
        parser.error("argument --delegated-creds is required when using service-account authentication")

    # If --update is used, --update-mode becomes mandatory.
    if args.update and not args.update_mode:
        parser.error("argument --update-mode is required when --update is used.")
    
    # Validate date range if both from-date and to-date are provided
    if args.from_date and args.to_date and args.from_date >= args.to_date:
        parser.error("--from-date must be earlier than --to-date")

    # Determine verbosity level
    if args.quiet:
        verbosity = 0
        log_level = logging.ERROR
    else:
        # Default is 1, each -v increases by 1
        verbosity = args.verbose + 1
        # Map verbosity to logging levels
        log_levels = {
            0: logging.ERROR,    # Quiet mode
            1: logging.WARNING,  # Default minimal 
            2: logging.INFO,     # -v: Show application details
            3: logging.DEBUG     # -vv: Show all details including API calls
        }
        log_level = log_levels.get(verbosity, logging.DEBUG)

    # Setup logging - explicitly use stderr to avoid interference with progress display
    # Only show our application logs, suppress HTTP debug messages from libraries
    FORMAT = '%(asctime)s %(levelname)-8s %(message)s'
    logging.basicConfig(format=FORMAT, level=log_level, stream=sys.stderr)
    
    # Suppress HTTP debug messages from underlying libraries for cleaner output
    # Always suppress these for consistent formatting - we have our own structured logging
    logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
    logging.getLogger('httplib2').setLevel(logging.WARNING)
    logging.getLogger('googleapiclient.discovery').setLevel(logging.WARNING)
    logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.WARNING)
    logging.getLogger('googleapiclient._auth').setLevel(logging.WARNING)
    logging.getLogger('google.auth._default').setLevel(logging.WARNING)
    logging.getLogger('google_auth_oauthlib.flow').setLevel(logging.WARNING)
    logging.getLogger('googleapiclient.http').setLevel(logging.WARNING)  # This suppresses the URL debug messages

    # Determine collection type string for folder naming
    if args.update:
        current_collection_type_str = args.update_mode # 'diff' or 'append'
    else:
        current_collection_type_str = 'initial'

    # Current timestamp for naming (already renamed to consistent_timestamp_str by previous edit)
    consistent_timestamp_str = datetime.now(tz=tz.tzutc()).strftime('%Y-%m-%dT%H%M%SZ')

    # Handle --update option which now requires a target directory
    if args.update:
        if not os.path.isdir(args.update):
            structured_log(f"Update target folder '{args.update}' does not exist or is not a directory.", 'ERROR')
            sys.exit(1)
        original_path = args.update # Keep for reference if needed
        
        # Standardized new path for update mode
        update_type_folder_str = 'update-diff' if args.update_mode == 'diff' else 'update-append'
        new_path = f"collection_{consistent_timestamp_str}_{update_type_folder_str}_{args.gws_domain}"

        if verbosity >= 2:
            structured_log(f"Updating from: {original_path}", 'INFO')
        
        if not os.path.exists(new_path):
            os.makedirs(new_path)
        # Copy JSON log files and both CSV/JSON stats files from original collection
        for filename in os.listdir(original_path):
            # Copy JSON log files and both CSV and JSON stats files (but not CLI output files)
            if (filename.endswith('.json') and not filename.startswith('_stats_cli_output_')) or (filename.startswith('_stats_') and filename.endswith('.csv')):
                src_file = os.path.join(original_path, filename)
                dst_file = os.path.join(new_path, filename)
                try:
                    shutil.copy2(src_file, dst_file)
                    if verbosity >= 2:
                        if filename.startswith('_stats_'):
                            file_type = "stats file"
                        else:
                            file_type = "log file"
                        structured_log(f"Copied {file_type} {filename} to new collection directory", 'INFO')
                except Exception as e:
                    structured_log(f"Error copying {filename}: {e}", 'ERROR')
        args.output_path = new_path
        structured_log(f"New collection directory: {new_path}", 'INFO')
        update_enabled = True
    else:
        update_enabled = False
        # Standardized output path for initial collection
        args.output_path = f"collection_{consistent_timestamp_str}_initial_{args.gws_domain}"
        structured_log(f"No output path specified, using: {args.output_path}", 'INFO')
        if not os.path.exists(args.output_path):
            os.makedirs(args.output_path)

    # Convert apps argument to list
    if args.apps.strip().lower() == 'all':
        args.apps = Google.get_application_list()
    elif args.apps:
        args.apps = [a.strip().lower() for a in args.apps.split(',')]

    # Validate max_results
    if args.max_results < 1 or args.max_results > 1000:
        structured_log("max-results must be between 1 and 1000, setting to 1000", 'WARNING')
        args.max_results = 1000
        
    # Validate thread count
    if args.num_threads < 1:
        structured_log("threads must be at least 1, setting to 1", 'WARNING')
        args.num_threads = 1
    elif args.num_threads > 50:
        structured_log("High thread count (>50) may cause API rate limiting or resource issues", 'WARNING')

    # Validate write frequency
    if args.write_batch_size < 0:
        structured_log("write-batch-size must be 0 or positive, setting to 100000", 'WARNING')
        args.write_batch_size = 100000

    # Log authentication method
    if verbosity >= 1:
        if args.auth_method == 'oauth':
            structured_log(f"Using OAuth authentication", 'INFO')
            if verbosity >= 2:
                structured_log(f"OAuth port: {args.oauth_port}, token file: {args.token_file}", 'INFO')
        else:
            structured_log(f"Using Service Account authentication - automated access to all log types", 'INFO')
            if verbosity >= 2:
                structured_log(f"Delegated credentials: {args.delegated_creds}", 'INFO')

    # DEBUG: Show combined arguments to be used if verbose
    if verbosity >= 3:
        structured_log(f"Configuration: {vars(args)}", 'DEBUG')

    try:
        # Pass in verbosity level to Google class
        google_args = vars(args).copy()
        google_args['verbosity'] = verbosity
        google_args['update'] = update_enabled
        google_args['gws_domain'] = args.gws_domain
        google_args['update_mode'] = args.update_mode
        google_args['original_update_path'] = args.update
        google_args['consistent_timestamp'] = consistent_timestamp_str # Pass consistent timestamp
        google_args['auth_method'] = args.auth_method
        google_args['oauth_port'] = args.oauth_port
        google_args['token_file'] = args.token_file
        
        # Connect to Google API and get logs
        google = Google(**google_args)
        stats = google.get_logs(args.from_date, args.to_date)
        
        # Add CLI output file message to buffer first
        if verbosity >= 1:
            cli_output_path = os.path.join(google.output_path, google.cli_output_filename)
            completion_message = f"Wrote CLI output file to {cli_output_path}"
            timestamp = datetime.now(tz=tz.tzutc()).strftime('%Y-%m-%dT%H%M%SZ')
            output_line = f"[{timestamp}] | {'INFO':<12} | {'INFO':<25} | {completion_message}"
            # Add to buffer so it's included in the CLI output file
            google.cli_output_buffer.append(output_line)
            # Show on terminal immediately
            print(output_line)
        
        # Print execution summary to capture it in CLI buffer
        google.print_execution_summary()
        
        # Write CLI output file after execution summary is complete (now includes the CLI message)
        google._write_cli_output()
        
        # Exit with appropriate code
        if stats['errors'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        structured_log(f"Unhandled exception: {e}", 'ERROR')
        if verbosity >= 2:
            traceback.print_exc()
        sys.exit(1)