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
from datetime import datetime
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
    DEFAULT_APPLICATIONS = ['access_transparency', 'admin', 'calendar', 'chat', 'chrome', 'context_aware_access', 'data_studio', 'drive', 'gcp', 'gplus', 'groups', 'groups_enterprise', 'jamboard', 'keep', 'login', 'meet', 'mobile', 'rules', 'saml', 'token', 'user_accounts', 'vault']
    
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
        self.show_progress = kwargs.get('show_progress', True)  # Progress bar
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
        
        # Initialize credentials during startup (main thread)
        self._credentials = None
        if self.auth_method == 'oauth':
            if self.verbosity >= 1:
                logging.info("Initializing OAuth authentication...")
            # Set up OAuth credentials now in the main thread
            SCOPES = ['https://www.googleapis.com/auth/admin.reports.audit.readonly']
            self._credentials = self._get_oauth_credentials(SCOPES)
            if self.verbosity >= 1:
                logging.info("OAuth authentication completed successfully")
        
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
            logging.info(f"Initialized with {self.num_threads} threads, verbosity level {self.verbosity}")
            
        # Start time measurement
        self.start_time = time.time()
        
        # Initialize display tracking
        self._display_lines_count = 0
        self._counts_display_lines = 0
        self._last_display_update = 0  # Initialize display throttling
        
        # Initialize progress tracking for large collections
        self.app_activities = {}
        self.app_status = {}  # Track status: 'downloading', 'done'
        self.app_downloaded = {}  # Track downloaded counts for progress

        # For update mode, load previous stats for initial_collection_time
        self.previous_initial_times = {}
        if self.update:
            # Try to find the previous stats file in the original directory
            # (assume parent of output_path is the original collection)
            prev_dir = os.path.dirname(os.path.abspath(self.output_path.rstrip('/\\')))
            prev_stats = None
            for fname in os.listdir(prev_dir):
                if fname.startswith('stats_') and fname.endswith('.csv'):
                    prev_stats = os.path.join(prev_dir, fname)
                    break
            if prev_stats and os.path.exists(prev_stats):
                try:
                    with open(prev_stats, 'r', newline='') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            key = (row['application'], os.path.basename(row['file_path']))
                            self.previous_initial_times[key] = row.get('initial_collection_time', row.get('collection_time', self.collection_timestamp))
                except Exception as e:
                    logging.warning(f"Could not read previous stats file: {e}")

    @staticmethod
    def get_application_list():
        """ 
        Returns a list of valid applicationName parameters for the activities.list() API method 
        Note: this is the complete list of valid options, and some may not be valid on particular accounts.
        """
        try:
            r = requests.get('https://admin.googleapis.com/$discovery/rest?version=reports_v1', timeout=10)
            r.raise_for_status()
            return r.json()['resources']['activities']['methods']['list']['parameters']['applicationName']['enum']
        except (requests.RequestException, KeyError, json.JSONDecodeError) as e:
            logging.error(f"Error fetching application list: {e}")
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
            logging.warning(f"Error reading date from log file {log_file_path}: {e}")
            
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
                with self.log_lock:
                    logging.debug(f"Thread {threading.current_thread().name} created new API session using {self.auth_method}")
                    
            return service
            
        except Exception as e:
            with self.log_lock:
                logging.error(f"Failed to create Google API session: {e}")
            raise

    def _get_oauth_credentials(self, scopes):
        """
        Handle OAuth authentication flow (based on ALFA implementation)
        """
        creds = None
        
        if self.verbosity >= 2:
            with self.log_lock:
                logging.debug(f"Looking for OAuth token at: {self.token_file}")
                logging.debug(f"Token file exists: {os.path.exists(self.token_file)}")
        
        # Check if we have a saved token (ALFA approach)
        if os.path.exists(self.token_file):
            try:
                creds = Credentials.from_authorized_user_file(self.token_file)
                if self.verbosity >= 2:
                    with self.log_lock:
                        logging.info(f"Loaded existing OAuth token from {self.token_file}")
            except Exception as e:
                # Check if it's the specific refresh_token missing error
                if "missing fields refresh_token" in str(e):
                    if self.verbosity >= 1:
                        with self.log_lock:
                            logging.warning(f"Token missing refresh_token field. This is normal if you've previously authorized this app. Authentication will still work.")
                else:
                    if self.verbosity >= 1:
                        with self.log_lock:
                            logging.warning(f"Could not load existing token: {e}")
                
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
                        with self.log_lock:
                            logging.info(f"Manually loaded OAuth token from {self.token_file}")
                except Exception as e2:
                    if self.verbosity >= 1:
                        with self.log_lock:
                            logging.warning(f"Could not manually load token: {e2}")
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
                        with self.log_lock:
                            logging.info("Refreshed OAuth token")
                    # Save refreshed token
                    with open(self.token_file, 'w') as token:
                        token.write(creds.to_json())
                except Exception as e:
                    if self.verbosity >= 1:
                        with self.log_lock:
                            logging.warning(f"Token refresh failed: {e}")
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
                    with self.log_lock:
                        logging.warning(f"API error ({status_code}), retry {retry_attempt}/{self.RETRY_MAX_ATTEMPTS}")
                
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
                    with self.log_lock:
                        logging.warning(f"Unexpected error: {e}, retry {retry_attempt}/{self.RETRY_MAX_ATTEMPTS}")
                
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
            logging.error(f"Error calculating hash for {file_path}: {e}")
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
        Places the stats file in the parent directory of self.output_path.
        """
        try:
            # Determine parent directory of the collection folder (self.output_path)
            output_collection_parent_dir = os.path.dirname(os.path.abspath(self.output_path.rstrip('/\\')))
            if not output_collection_parent_dir: # If output_path was a top-level dir name like "collection_foo"
                output_collection_parent_dir = "." # Place in current working directory
            
            csv_path = os.path.join(output_collection_parent_dir, self.stats_filename)
            
            with open(csv_path, 'w', newline='') as csvfile:
                fieldnames = ['application', 'file_path', 'record_count', 'updated_record_count', 'file_size', 
                              'md5', 'sha1', 'collection_time', 'initial_collection_time', 'collection_type', 'original_update_path']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for stat in sorted(self.file_stats, key=lambda x: x['application']):
                    writer.writerow(stat)
            if self.verbosity >= 1:
                logging.info(f"Wrote stats file to {csv_path}")
        except Exception as e:
            logging.error(f"Error writing stats CSV: {e}")

    def _write_stats_json(self):
        """
        Write _stats_{timestamp}.json file with information about each log file.
        Places the stats file in the parent directory of self.output_path.
        """
        try:
            output_collection_parent_dir = os.path.dirname(os.path.abspath(self.output_path.rstrip('/\\')))
            if not output_collection_parent_dir:
                output_collection_parent_dir = "."
            
            json_path = os.path.join(output_collection_parent_dir, self.stats_json_filename)
            
            # Ensure self.file_stats is sorted by application for consistent output
            sorted_stats = sorted(self.file_stats, key=lambda x: x.get('application', ''))
            
            with open(json_path, 'w') as jsonfile:
                json.dump(sorted_stats, jsonfile, indent=4)
            
            if self.verbosity >= 1:
                logging.info(f"Wrote JSON stats file to {json_path}")
        except Exception as e:
            logging.error(f"Error writing JSON stats file: {e}")

    def get_logs(self, from_date=None):
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
            logging.info(f"Starting log collection for {len(self.app_list)} applications using {self.num_threads} threads")
            if self.update:
                logging.info(f"Running in update mode (mode: {self.update_mode}) - behavior depends on mode.")
        
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
                        with self.log_lock:
                            logging.info(f"Skipping {app} (no original file or file is empty) in append mode.")
                    skip_app = True
                    skipped_apps.add(app)
                    # For skipped apps, their entry in self.file_stats_dict remains the default one created above.
            
            if not skip_app:
                if self.verbosity >= 2:
                    with self.log_lock:
                        logging.info(f"Checking most recent date for {app} (if applicable for update)...")
                # For update modes, _check_recent_date on the *new* output_file (which would have been copied)
                # or from_date if file is new or _check_recent_date fails.
                app_from_date = self._check_recent_date(output_file) or from_date
                if self.verbosity >= 2 and app_from_date:
                    with self.log_lock:
                        logging.info(f"Will only fetch {app} logs after {app_from_date}")
                tasks.append((app, output_file, app_from_date))
        
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
            print("Collecting logs...")
            # Reset display lines count for collection phase
            self._display_lines_count = 0
            self._display_activity_status()
        
        # Create a thread pool
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            # Submit each app to the thread pool
            futures = {
                executor.submit(
                    self._get_activity_logs,
                    app_task, # Renamed to avoid clash with loop var 'app'
                    output_file_task, # Renamed
                    only_after_datetime_task # Renamed
                ): (app_task, output_file_task) for app_task, output_file_task, only_after_datetime_task in tasks
            }
            
            # Mark all submitted apps as in progress
            for app_task, output_file_task, only_after_datetime_task in tasks:
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
                        if self.verbosity >= 1: logging.warning(f"Could not recount lines for {output_file_processed}: {e_recount}")
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
                        with self.log_lock:
                            logging.info(f"Completed {app_processed}: saved {newly_written_for_app} of {fetched_from_api_for_app} API entries. File has {actual_record_count_in_file} records.")
                            
                except Exception as e_future:
                    if self.verbosity >= 1: logging.error(f"Error processing {app_processed}: {e_future}")
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
                    if self.verbosity >= 0: logging.error(f"CRITICAL: App {app_processed} from future not found in pre-populated stats dictionary! Adding it now.")
                    self.file_stats_dict[app_processed] = current_app_stats_dict_entry # Add if somehow missing
                    
                # Update progress tracking
                self.apps_in_progress.discard(app_processed)  # Remove from in-progress
                self.apps_done.add(app_processed)  # Add to completed
                self.apps_completed += 1
                
                # Update progress display
                if self.verbosity >= 1:
                    self._display_activity_status()
            
        # Final display
        if self.verbosity >= 1:
            self._display_activity_status(final=True)
        
        # Convert the dictionary of stats to a list for CSV writing and other uses
        self.file_stats = list(self.file_stats_dict.values())
        
        # Write stats CSV file with timestamp (after all apps are ensured present and updated)
        self._write_stats_csv() # _write_stats_csv sorts by application before writing
        
        # Write stats JSON file with timestamp (after all apps are ensured present and updated)
        self._write_stats_json() # _write_stats_json sorts by application before writing
        
        # Calculate elapsed time
        elapsed = time.time() - operation_start
        
        # Final summary - always show this regardless of verbosity
        logging.info(f"COMPLETED IN {elapsed:.2f}s: Saved {self.stats['total_saved']} of {self.stats['total_found']} records from API calls this run.")
        
        if self.verbosity >= 2:
            logging.info(f"API Calls: {self.stats['api_calls']}, Retries: {self.stats['retries']}, Errors: {self.stats['errors']}")
        
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
            # Move cursor up to overwrite previous output (except for first time)
            if hasattr(self, '_display_lines_count') and self._display_lines_count > 0:
                # Safety limit on cursor movement
                lines_to_clear = min(self._display_lines_count, 50)  # Max 50 lines
                for _ in range(lines_to_clear):
                    print("\033[F\033[K", end="")  # Move up and clear line
        
            lines_printed = 0
        
            # Show applications in simplified tab-delimited format: downloaded activities - STATUS
            for app in sorted(self.app_list):
                downloaded_count = self.app_downloaded.get(app, 0)
            
                # Determine status indicator
                if app in self.apps_done:
                    status = "DONE"
                elif app in self.apps_in_progress:
                    status = "DOWNLOADING..."
                elif hasattr(self, 'app_status') and self.app_status.get(app) == 'unsupported':
                    status = "UNSUPPORTED"
                else:
                    status = ""
            
                # Show downloaded count only (no totals or percentages)
                count_display = f"{downloaded_count}"
                print(f"{app:>25}:\t{count_display:>10} activities - {status}")
                lines_printed += 1
        
            # Show progress bar at the bottom (only if not final or if we want to show completion)
            if self.apps_total > 0:
                progress_pct = (self.apps_completed / self.apps_total) * 100
                elapsed = time.time() - self.start_time
                rate = self.apps_completed / elapsed if elapsed > 0 else 0
                remaining = (self.apps_total - self.apps_completed) / rate if rate > 0 and not final else 0
            
                progress_line = f"Overall Progress: {progress_pct:3.0f}% | {self.apps_completed}/{self.apps_total} [{elapsed:05.2f}<{remaining:05.2f}, {rate:5.2f}app/s]"
                print(progress_line)
                lines_printed += 1
        
            if final:
                print()  # Add extra line at the end for spacing before summary
                lines_printed += 1
        
            # Store the number of lines we printed for next time
            self._display_lines_count = lines_printed
            
        finally:
            # Always reset the display flag
            self._display_in_progress = False

    def _handle_unsupported_app_error(self, application_name, total_count=0):
        """Handle unsupported application errors gracefully to prevent display corruption"""
        if hasattr(self, 'app_status'):
            self.app_status[application_name] = 'unsupported'
        return total_count

    def _write_entries_to_file(self, entries, output_file, mode='a'):
        """Helper method to write entries to file with proper formatting"""
        try:
            with open(output_file, mode) as f:
                for entry in entries:
                    f.write(entry.rstrip() + '\n')
            return True
        except Exception as e:
            with self.log_lock:
                logging.error(f"Error writing to {output_file}: {e}")
            return False

    def _get_activity_logs(self, application_name, output_file, only_after_datetime=None):
        """ Collect activity logs from the specified application with pagination support and incremental writing """
        if self.verbosity >= 2:
            with self.log_lock:
                logging.info(f"Starting collection for {application_name}...")
        
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
                                with self.log_lock:
                                    logging.warning(f"Error parsing existing entry for deduplication: {e}")
                if self.verbosity >= 2:
                    with self.log_lock:
                        logging.info(f"Loaded {len(existing_entries)} existing entries for deduplication in {application_name}")
            except Exception as e:
                with self.log_lock:
                    logging.error(f"Error reading existing file for deduplication: {e}")
                existing_entries = set()
                existing_lines = []
            new_entries = []
            try:
                while True:
                    page_count += 1
                    if self.verbosity >= 3:
                        with self.log_lock:
                            logging.debug(f"Fetching page {page_count} for {application_name}...")
                    try:
                        results = self._api_call_with_retry(
                            service.activities().list,
                            userKey='all',
                            applicationName=application_name,
                            maxResults=self.max_results,
                            pageToken=page_token
                        )
                    except Exception as e:
                        error_str = str(e)
                        if "does not match the pattern" in error_str:
                            with self.log_lock:
                                if self.auth_method == 'service-account':
                                    logging.warning(f"Application '{application_name}' not supported with Service Account authentication. Try --auth-method oauth for full access.")
                                else:
                                    logging.warning(f"Application '{application_name}' not supported by API (not available for this Google Workspace account/edition)")
                        else:
                            with self.log_lock:
                                logging.error(f"Failed to fetch logs for {application_name}: {e}")
                        with self.stats_lock:
                            self.stats['errors'] += 1
                        return 0, len(existing_entries)
                    activities = results.get('items', [])
                    page_activities = len(activities)
                    total_activities += page_activities
                    
                    page_token = results.get('nextPageToken')
                    if self.verbosity >= 3:
                        with self.log_lock:
                            logging.debug(f"{application_name}: Page {page_count} has {page_activities} activities, next token: {page_token}")
                    if activities:
                        for entry in activities[::-1]:
                            # Only new records after a certain date
                            if only_after_datetime:
                                try:
                                    entry_datetime = dateparser.parse(entry['id']['time'])
                                    if entry_datetime <= only_after_datetime:
                                        continue
                                except (KeyError, ValueError, TypeError) as e:
                                    if self.verbosity >= 3:
                                        with self.log_lock:
                                            logging.warning(f"Invalid date in entry: {e}")
                                    continue
                            try:
                                entry_id_dict = entry.get('id', {})
                                entry_id = f"{entry_id_dict.get('time', '')}-{entry_id_dict.get('uniqueQualifier', '')}"
                            except Exception as e:
                                if self.verbosity >= 3:
                                    with self.log_lock:
                                        logging.warning(f"Error building entry_id: {e}")
                                continue
                            if entry_id in existing_entries:
                                if self.verbosity >= 3:
                                    with self.log_lock:
                                        logging.debug(f"Skipping duplicate entry: {entry_id}")
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
                        with self.log_lock:
                            logging.info(f"Wrote {len(new_entries)} new entries to {output_file} (diff mode)")
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
                        with self.log_lock:
                            logging.info(f"Wrote {len(new_entries)} new entries to {output_file} with deduplication. Total unique: {len(existing_lines) + len(new_entries)}")
                    # After writing, recount the lines for record_count
                    try:
                        with open(output_file, 'r') as f:
                            total_lines = sum(1 for _ in f if _.strip())
                    except Exception:
                        total_lines = 0
            except Exception as e:
                with self.log_lock:
                    logging.error(f"Error processing file {output_file} for {application_name}: {e}")
                with self.stats_lock:
                    self.stats['errors'] += 1
                total_lines = len(existing_entries) + len(new_entries)
            
            # Return new records added, and total records in file
            return output_count, total_activities
        else:
            # Normal logic for initial collection with incremental writing
            written_entries = []  # Track all entries for final write
                
            try:
                while True:
                    page_count += 1
                    if self.verbosity >= 3:
                        with self.log_lock:
                            logging.debug(f"Fetching page {page_count} for {application_name}...")
                    try:
                        results = self._api_call_with_retry(
                            service.activities().list,
                            userKey='all',
                            applicationName=application_name,
                            maxResults=self.max_results,
                            pageToken=page_token
                        )
                    except Exception as e:
                        error_str = str(e)
                        if "does not match the pattern" in error_str:
                            with self.log_lock:
                                if self.auth_method == 'service-account':
                                    logging.warning(f"Application '{application_name}' not supported with Service Account authentication. Try --auth-method oauth for full access.")
                                else:
                                    logging.warning(f"Application '{application_name}' not supported by API (not available for this Google Workspace account/edition)")
                        else:
                            with self.log_lock:
                                logging.error(f"Failed to fetch logs for {application_name}: {e}")
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
                        with self.log_lock:
                            logging.debug(f"{application_name}: Page {page_count} has {page_activities} activities, next token: {page_token}")
                            
                    if activities:
                        for entry in activities[::-1]:
                            if only_after_datetime:
                                try:
                                    entry_datetime = dateparser.parse(entry['id']['time'])
                                    if entry_datetime <= only_after_datetime:
                                        continue
                                except (KeyError, ValueError, TypeError) as e:
                                    if self.verbosity >= 3:
                                        with self.log_lock:
                                            logging.warning(f"Invalid date in entry: {e}")
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
                                            with self.log_lock:
                                                logging.info(f"Incremental write: {len(written_entries)} records written to {application_name}")
                                        
                                        # Update progress tracking only when batch is written to disk
                                        self.app_downloaded[application_name] = output_count
                                        self.app_activities[application_name] = output_count
                                        
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
                                    
                                    if self.verbosity >= 1:
                                        current_time = time.time()
                                        # Only update display if enough time has passed (minimum 0.5 seconds between updates)
                                        if current_time - self._last_display_update >= 0.5:
                                            self._display_activity_status()
                                            self._last_display_update = current_time
                                
                    if not page_token:
                        break
                        
            except Exception as e:
                with self.log_lock:
                    logging.error(f"Error during collection for {application_name}: {e}")
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
            
        # Print summary
        print("\n" + "="*80)
        print(f"EXECUTION SUMMARY")
        print("="*80)
        print(f"Total execution time: {time_str}")
        print(f"Applications processed: {len(self.app_list)}")
        print(f"Records found: {self.stats['total_found']}")
        print(f"Records saved: {self.stats['total_saved']}")
        print(f"Collection type: {self.collection_type.upper()}")
        print(f"Collection folder: {os.path.abspath(self.output_path)}")
        
        # Stats file information - path adjusted to parent directory
        output_collection_parent_dir = os.path.dirname(os.path.abspath(self.output_path.rstrip('/\\')))
        if not output_collection_parent_dir:
            output_collection_parent_dir = "."
        stats_csv_path = os.path.join(output_collection_parent_dir, self.stats_filename)
        
        if os.path.exists(stats_csv_path):
            print(f"Stats file (CSV): {stats_csv_path}")
        
        # JSON Stats file information
        stats_json_path = os.path.join(output_collection_parent_dir, self.stats_json_filename)
        if os.path.exists(stats_json_path):
            print(f"Stats file (JSON): {stats_json_path}")
            
        if self.verbosity >= 2:
            print(f"API calls: {self.stats['api_calls']}")
            print(f"API retries: {self.stats['retries']}")
            print(f"Errors: {self.stats['errors']}")
            
        if self.stats['total_found'] > 0:
            # Calculate throughput
            records_per_second = self.stats['total_found'] / total_execution_time
            print(f"Throughput: {records_per_second:.2f} records/second")
            
        print("="*80)


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

    # Setup logging
    FORMAT = '%(asctime)s %(levelname)-8s %(message)s'
    logging.basicConfig(format=FORMAT, level=log_level)

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
            logging.error(f"Update target folder '{args.update}' does not exist or is not a directory.")
            sys.exit(1)
        original_path = args.update # Keep for reference if needed
        
        # Standardized new path for update mode
        update_type_folder_str = 'update-diff' if args.update_mode == 'diff' else 'update-append'
        new_path = f"collection_{consistent_timestamp_str}_{update_type_folder_str}_{args.gws_domain}"

        if verbosity >= 2:
            logging.info(f"Updating from: {original_path}")
        
        if not os.path.exists(new_path):
            os.makedirs(new_path)
        # Copy logic remains the same, using new_path as destination
        for filename in os.listdir(original_path):
            if filename.endswith('.json'):
                src_file = os.path.join(original_path, filename)
                dst_file = os.path.join(new_path, filename)
                try:
                    shutil.copy2(src_file, dst_file)
                    if verbosity >= 2:
                        logging.info(f"Copied {filename} to new collection directory")
                except Exception as e:
                    logging.error(f"Error copying {filename}: {e}")
        args.output_path = new_path
        logging.info(f"New collection directory: {new_path}")
        update_enabled = True
    else:
        update_enabled = False
        # Standardized output path for initial collection
        args.output_path = f"collection_{consistent_timestamp_str}_initial_{args.gws_domain}"
        logging.info(f"No output path specified, using: {args.output_path}")
        if not os.path.exists(args.output_path):
            os.makedirs(args.output_path)

    # Convert apps argument to list
    if args.apps.strip().lower() == 'all':
        args.apps = Google.get_application_list()
    elif args.apps:
        args.apps = [a.strip().lower() for a in args.apps.split(',')]

    # Validate max_results
    if args.max_results < 1 or args.max_results > 1000:
        logging.warning("max-results must be between 1 and 1000, setting to 1000")
        args.max_results = 1000
        
    # Validate thread count
    if args.num_threads < 1:
        logging.warning("threads must be at least 1, setting to 1")
        args.num_threads = 1
    elif args.num_threads > 50:
        logging.warning("High thread count (>50) may cause API rate limiting or resource issues")

    # Validate write frequency
    if args.write_batch_size < 0:
        logging.warning("write-batch-size must be 0 or positive, setting to 100000")
        args.write_batch_size = 100000

    # Log authentication method
    if verbosity >= 1:
        if args.auth_method == 'oauth':
            logging.info(f"Using OAuth authentication - supports all log types including Keep")
            if verbosity >= 2:
                logging.info(f"OAuth port: {args.oauth_port}, token file: {args.token_file}")
        else:
            logging.info(f"Using Service Account authentication - automated access to all log types")
            if verbosity >= 2:
                logging.info(f"Delegated credentials: {args.delegated_creds}")

    # DEBUG: Show combined arguments to be used if verbose
    if verbosity >= 3:
        logging.debug(f"Configuration: {vars(args)}")

    try:
        # Pass in verbosity level to Google class
        google_args = vars(args).copy()
        google_args['verbosity'] = verbosity
        google_args['show_progress'] = not args.no_progress
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
        stats = google.get_logs(args.from_date)
        
        # Print execution summary
        google.print_execution_summary()
        
        # Exit with appropriate code
        if stats['errors'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Unhandled exception: {e}")
        if verbosity >= 2:
            traceback.print_exc()
        sys.exit(1)