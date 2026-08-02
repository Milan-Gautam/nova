#!/usr/bin/env python3
"""
███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ 
████╗  ██║██╔═══██╗██║   ██║██╔══██╗
██╔██╗ ██║██║   ██║██║   ██║███████║
██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
                                      
NOVA - Next-gen Online Vulnerability Analyzer
Advanced JavaScript Enumeration & Endpoint Discovery Engine
Version: 2.2.0 | Codename: Supernova
Author: Expert Pentester | Type: Reconnaissance
Pipeline Ready | Batch Processing | Multi-Target Support

CHANGELOG (2.2.0):
  - FIX: Style.RESETALL typo (Style.RESET_ALL) that crashed the CLI on every run, incl. --help
  - FIX: retry handler now actually retries on 429/500/502/503/504 (previously dead code,
    since fetch() returned None on non-200 before the retry handler ever saw a status code)
  - FIX: crawl() and JS-chain following now run concurrently under the semaphore instead of
    sequentially awaiting one link/file at a time
  - FIX: removed silent links[:10] cap during crawling that was dropping links with no warning
  - ADD: real passive-enumeration phase (Wayback/OTX/urlscan) wired to --no-passive
  - ADD: relative-path endpoint resolution -- any absolute-path reference found inside a JS
    file (e.g. "/constructor/main.js", "/internal/config.json") is now resolved to a full
    scheme://domain URL instead of being ignored or left as a bare path
  - FIX: per-target rate limiter (previously one shared limiter throttled all concurrent
    targets together)
  - REMOVED: unused NovaValidator.CDN_DOMAINS (dead code) - superseded by
    FALSE_POSITIVE_DOMAINS check which is actually used
"""

import re
import sys
import json
import asyncio
import aiohttp
import argparse
import hashlib
import logging
import os
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import Set, Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import OrderedDict
from enum import Enum
import textwrap
from colorama import init, Fore, Back, Style

# Initialize colorama
init(autoreset=True)

# Custom logging with colors
class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors"""

    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Back.WHITE,
    }

    def format(self, record):
        log_color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{log_color}{record.levelname}{Style.RESET_ALL}"
        record.msg = f"{log_color}{record.msg}{Style.RESET_ALL}"
        return super().format(record)

logger = logging.getLogger('NOVA')
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(ColoredFormatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S'))
logger.addHandler(console_handler)

file_handler = logging.FileHandler('nova.log')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)


class ScanMode(Enum):
    STEALTH = "stealth"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"
    INSANE = "insane"


@dataclass
class JSFile:
    url: str
    source: str
    content_hash: Optional[str] = None
    size: Optional[int] = None
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    endpoints: Set[str] = field(default_factory=set)
    secrets: Set[str] = field(default_factory=set)
    discovered_at: datetime = field(default_factory=datetime.now)

    def __hash__(self):
        return hash(self.url)

    def __eq__(self, other):
        return self.url == other.url


@dataclass
class TargetResult:
    target_url: str
    domain: str
    all_targets: List[str] = field(default_factory=list)
    js_files: Dict[str, JSFile] = field(default_factory=OrderedDict)
    endpoints: Set[str] = field(default_factory=set)
    secrets: Set[str] = field(default_factory=set)
    stats: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    success: bool = True


@dataclass
class NovaConfig:
    target_urls: List[str] = field(default_factory=list)
    target_file: Optional[str] = None
    read_from_stdin: bool = False

    mode: ScanMode = ScanMode.NORMAL

    max_threads: int = 10
    max_depth: int = 3
    timeout: int = 30
    retries: int = 3
    retry_delay: float = 1.0
    rate_limit: float = 0.1
    concurrent_targets: int = 3

    max_js_size: int = 10 * 1024 * 1024
    max_pages: int = 1000
    max_js_files: int = 10000
    max_links_per_page: int = 200  # was a silent hard cap of 10; now configurable & logged

    verify_ssl: bool = False
    follow_redirects: bool = True
    max_redirects: int = 5
    proxy: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

    passive_scan: bool = True
    brute_force: bool = True
    deep_analysis: bool = True
    extract_endpoints: bool = True
    extract_secrets: bool = True
    follow_js_chains: bool = True
    scope_domain: bool = True

    output_dir: str = 'nova_output'
    output_format: str = 'all'
    merge_results: bool = False
    quiet: bool = False

    def __post_init__(self):
        if self.mode == ScanMode.STEALTH:
            self.max_threads = min(3, self.max_threads)
            self.max_depth = min(1, self.max_depth)
            self.rate_limit = max(2.0, self.rate_limit)
            self.retries = min(1, self.retries)
            self.brute_force = False
            self.passive_scan = False
            self.concurrent_targets = 1

        elif self.mode == ScanMode.AGGRESSIVE:
            self.max_threads = max(20, self.max_threads)
            self.max_depth = max(5, self.max_depth)
            self.rate_limit = min(0.01, self.rate_limit)
            self.retries = max(5, self.retries)
            self.concurrent_targets = max(5, self.concurrent_targets)

        elif self.mode == ScanMode.INSANE:
            self.max_threads = max(50, self.max_threads)
            self.max_depth = max(10, self.max_depth)
            self.rate_limit = 0
            self.retries = max(10, self.retries)
            self.max_pages = 10000
            self.max_js_files = 100000
            self.concurrent_targets = 10


class NovaRateLimiter:
    """Rate limiter with burst support. One instance PER TARGET (see NOVA.process_target)."""

    def __init__(self, rate: float, burst: int = 10):
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last_update = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            if self.rate == 0:
                return

            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_update = now

            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class RetryableStatusError(Exception):
    """Raised internally so NovaRetryHandler can catch and back off on retryable HTTP statuses."""

    def __init__(self, status: int):
        self.status = status
        super().__init__(f"Retryable status: {status}")


class NovaRetryHandler:
    """Retry with exponential backoff. Now actually triggers on 429/500/502/503/504."""

    def __init__(self, max_retries: int = 3, base_delay: float = 1.0, max_delay: float = 60.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.retryable_statuses = {429, 500, 502, 503, 504}

    async def execute(self, func, *args, **kwargs):
        last_exception = None

        for attempt in range(self.max_retries + 1):
            try:
                return await func(*args, **kwargs)
            except (aiohttp.ClientError, asyncio.TimeoutError, RetryableStatusError) as e:
                last_exception = e
                if attempt < self.max_retries:
                    delay = min(self.base_delay * (2 ** attempt) + (attempt * 0.1), self.max_delay)
                    await asyncio.sleep(delay)

        raise last_exception


class NovaValidator:
    """Validates discovered resources"""

    FALSE_POSITIVE_DOMAINS = {
        'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
    }

    @staticmethod
    def is_valid_js_url(url: str) -> bool:
        if not url:
            return False

        url = url.strip().strip('"\'').strip('`')

        if not re.search(r'\.js(?:\?|#|$)', url, re.IGNORECASE):
            return False

        if url.startswith(('data:', 'blob:', 'file:', 'javascript:')):
            return False

        parsed = urlparse(url)
        if parsed.netloc in NovaValidator.FALSE_POSITIVE_DOMAINS:
            return False

        if re.search(r'\.js\.(map|html?|php|asp)$', url, re.IGNORECASE):
            return False

        return True

    @staticmethod
    def is_valid_js_content(content: str, content_type: str = '') -> bool:
        """
        Reject soft-404 HTML pages served with a 200 status on a .js URL.
        Do NOT try to positively confirm "this looks like JS" via keyword
        matching -- minified/bundled output from esbuild, Vite, Rollup,
        Terser, etc. frequently writes `import{x}from"y"`, `const{a}=b`,
        single-character re-export shims, or pure-comment/license-header
        files with no keyword ever appearing in the checked window. Those
        are all valid JS. Requiring a keyword match (previous behavior)
        silently dropped real JS files with zero indication why.
        """
        if not content or len(content) < 1:
            return False

        if content_type:
            ct = content_type.lower().split(';')[0].strip()
            if ct in ('text/html', 'application/xhtml+xml', 'text/xml',
                      'application/xml', 'text/css'):
                return False

        # Look further in than 200 chars -- large license-header comment
        # blocks (common when bundling multiple libraries) can easily
        # exceed 200 chars before any doctype/html tag would appear anyway.
        head = content[:1000].lower().lstrip()
        if head.startswith(('<!doctype', '<html', '<?xml')):
            return False
        # A body tag appearing in the very first bytes is a strong signal
        # of an HTML error/soft-404 page rather than JS with a stray
        # string literal containing "<body" somewhere later in the file.
        if '<body' in content[:300].lower():
            return False

        return True


class NovaBanner:
    @staticmethod
    def display(config: NovaConfig = None):
        banner = f"""
{Fore.CYAN}{Style.BRIGHT}
    ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ 
    ████╗  ██║██╔═══██╗██║   ██║██╔══██╗
    ██╔██╗ ██║██║   ██║██║   ██║███████║
    ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
    ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
    ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.GREEN}{Style.BRIGHT}┌─────────────────────────────────────────────────────┐
│  NOVA - Next-gen Online Vulnerability Analyzer      │
│  Advanced JS Enumeration & Endpoint Discovery        │
│  Version: 2.2.0 | Codename: Supernova                │
│  Pipeline Ready | Batch Processing                   │
└─────────────────────────────────────────────────────┘{Style.RESET_ALL}
"""
        print(banner)

        if config:
            mode_color = {
                ScanMode.STEALTH: Fore.BLUE,
                ScanMode.NORMAL: Fore.GREEN,
                ScanMode.AGGRESSIVE: Fore.YELLOW,
                ScanMode.INSANE: Fore.RED,
            }.get(config.mode, Fore.WHITE)

            target_count = len(config.target_urls) if config.target_urls else 0
            target_source = "STDIN" if config.read_from_stdin else "FILE" if config.target_file else "CLI"

            print(f"{Fore.YELLOW}{Style.BRIGHT}[*] Scan Configuration:{Style.RESET_ALL}")
            print(f"    Targets: {Fore.WHITE}{target_count} URLs{Style.RESET_ALL} (Source: {target_source})")
            print(f"    Mode: {mode_color}{config.mode.value.upper()}{Style.RESET_ALL}")
            print(f"    Threads: {config.max_threads} | Depth: {config.max_depth}")
            print(f"    Concurrent Targets: {config.concurrent_targets}")
            print(f"    Rate Limit: {config.rate_limit}s/req | Retries: {config.retries}")

            features = []
            if config.passive_scan: features.append("Passive")
            if config.brute_force: features.append("Brute")
            if config.deep_analysis: features.append("Deep")
            if config.extract_endpoints: features.append("Endpoints")
            if config.extract_secrets: features.append("Secrets")

            print(f"    Features: {Fore.GREEN}{', '.join(features)}{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")


class TargetLoader:
    @staticmethod
    def from_stdin() -> List[str]:
        targets = []
        if not sys.stdin.isatty():
            logger.info(f"{Fore.CYAN}[INPUT]{Style.RESET_ALL} Reading targets from stdin...")
            for line in sys.stdin:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
            logger.info(f"{Fore.GREEN}[INPUT]{Style.RESET_ALL} Loaded {len(targets)} targets from stdin")
        else:
            logger.warning(f"{Fore.YELLOW}[INPUT]{Style.RESET_ALL} No stdin data detected")
        return targets

    @staticmethod
    def from_file(filename: str) -> List[str]:
        targets = []
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
            logger.info(f"{Fore.GREEN}[INPUT]{Style.RESET_ALL} Loaded {len(targets)} targets from {filename}")
        except FileNotFoundError:
            logger.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} File not found: {filename}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error reading file: {e}")
            sys.exit(1)
        return targets

    @staticmethod
    def normalize_targets(targets: List[str]) -> List[str]:
        normalized = []
        for target in targets:
            if not target.startswith(('http://', 'https://')):
                target = f"https://{target}"
            target = target.rstrip('/')
            try:
                parsed = urlparse(target)
                if parsed.netloc:
                    normalized.append(target)
                else:
                    logger.warning(f"{Fore.YELLOW}[SKIP]{Style.RESET_ALL} Invalid URL: {target}")
            except Exception:
                logger.warning(f"{Fore.YELLOW}[SKIP]{Style.RESET_ALL} Invalid URL: {target}")
        return normalized


class NOVA:
    """NOVA - Main Engine with Multi-Target Support"""

    def __init__(self, config: NovaConfig):
        self.config = config
        self.validator = NovaValidator()

        self.all_results: Dict[str, TargetResult] = OrderedDict()
        self.global_stats = {
            'total_targets': 0,
            'total_inputs': 0,
            'successful_targets': 0,
            'failed_targets': 0,
            'total_js_files': 0,
            'total_endpoints': 0,
            'total_secrets': 0,
            'start_time': None,
            'end_time': None,
        }

        os.makedirs(config.output_dir, exist_ok=True)

    async def process_target(self, target_urls: List[str], target_domain: str, target_dir: str) -> TargetResult:
        # target_urls are ALL the raw inputs that share this one domain
        # (could be one URL, or a mix of page URLs and/or direct JS file
        # URLs -- e.g. a list of JS files all on the same host). Every one
        # of them feeds into ONE shared js_files/endpoints/secrets state
        # and ONE output directory, instead of each getting its own
        # directory keyed only by domain -- which previously meant two
        # targets on the same host would race to truncate/overwrite each
        # other's output files.
        target_scheme = urlparse(target_urls[0]).scheme or 'https'

        # Create the target's output directory and open live-write files NOW,
        # before any scanning happens. Previously all output was buffered in
        # memory and only written once, at the very end of the ENTIRE batch,
        # in _save_results(). That meant a long scan, a scan on a later
        # target that errors out, or the process being interrupted mid-run
        # lost everything found so far -- even though it was printing
        # "[+] Found JS: ..." to the console the whole time. Now every
        # discovered JS file / endpoint / secret is appended to disk
        # immediately, as it's found.
        os.makedirs(target_dir, exist_ok=True)
        live_js_path = os.path.join(target_dir, 'js_files.txt')
        live_endpoints_path = os.path.join(target_dir, 'endpoints.txt')
        live_secrets_path = os.path.join(target_dir, 'secrets.txt')
        # Truncate any stale files from a previous run of the same target in
        # this output dir before appending fresh results.
        open(live_js_path, 'w').close()
        open(live_endpoints_path, 'w').close()
        open(live_secrets_path, 'w').close()

        def live_append(path: str, line: str):
            # Synchronous append is safe here: this is asyncio single-threaded
            # code with no `await` between open/write/close, so there's no
            # interleaving between coroutines on this file.
            try:
                with open(path, 'a') as f:
                    f.write(line + '\n')
            except Exception as e:
                logger.debug(f"[SAVE-FAIL] Could not write to {path}: {e}")

        result = TargetResult(
            target_url=target_urls[0],
            domain=target_domain,
            all_targets=list(target_urls),
            start_time=datetime.now(),
        )

        js_files: Dict[str, JSFile] = OrderedDict()
        endpoints: Set[str] = set()
        secrets: Set[str] = set()
        crawled_urls: Set[str] = set()
        # Reserved synchronously (before any await) the moment a JS URL is
        # queued, so two concurrent chains that both reference the same
        # file (e.g. a shared vendor.js) don't both slip past the
        # `js_url in js_files` check and fetch it twice -- js_files only
        # gets its entry AFTER the fetch completes, which left a window
        # for duplicate work under concurrency. Deliberately never removed
        # on failure either -- once a URL has been attempted (success or
        # not) there's no benefit to a second source re-triggering the
        # same failed fetch.
        in_flight: Set[str] = set()

        # Per-target instances -- fixes shared-rate-limiter/retry-handler bleed across targets
        rate_limiter = NovaRateLimiter(self.config.rate_limit)
        retry_handler = NovaRetryHandler(self.config.retries, self.config.retry_delay)

        stats = {
            'requests_made': 0,
            'requests_successful': 0,
            'requests_failed': 0,
            'requests_retried': 0,
            'js_files_found': 0,
            'false_positives_filtered': 0,
            'endpoints_discovered': 0,
            'secrets_found': 0,
            'pages_crawled': 0,
            'js_analyzed': 0,
            'passive_hits': 0,
        }

        connector = aiohttp.TCPConnector(
            limit=self.config.max_threads,
            limit_per_host=self.config.max_threads,
            ssl=self.config.verify_ssl,
        )

        timeout = aiohttp.ClientTimeout(total=self.config.timeout)

        headers = {
            'User-Agent': self.config.user_agent,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        headers.update(self.config.headers)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
            cookies=self.config.cookies,
        ) as session:

            semaphore = asyncio.Semaphore(self.config.max_threads)

            def resolve_url(url: str, base_url: str) -> Optional[str]:
                """Resolve any URL/path found in HTML or JS to an absolute URL."""
                if not url or not base_url:
                    return None

                url = url.strip().strip('"\'').strip('`')
                url = url.split('#')[0].split('?')[0]

                if not url or url.startswith(('data:', 'blob:', 'file:', 'javascript:', 'mailto:')):
                    return None

                try:
                    if url.startswith(('http://', 'https://')):
                        parsed = urlparse(url)
                        if self.config.scope_domain:
                            if target_domain in parsed.netloc:
                                return url
                            return None
                        return url

                    if url.startswith('//'):
                        return f"{target_scheme}:{url}"

                    # Absolute path e.g. "/constructor/main.js" -- attach full scheme+domain
                    if url.startswith('/'):
                        return f"{target_scheme}://{target_domain}{url}"

                    resolved = urljoin(base_url, url)
                    parsed = urlparse(resolved)

                    if self.config.scope_domain:
                        if target_domain not in parsed.netloc:
                            return None

                    return resolved
                except Exception:
                    return None

            async def fetch(url: str, method: str = 'GET', _retry_as_crawler: bool = True) -> Optional[Tuple[aiohttp.ClientResponse, Optional[str]]]:
                async with semaphore:
                    await rate_limiter.acquire()
                    stats['requests_made'] += 1

                    async def do_request(extra_headers: Optional[Dict[str, str]] = None):
                        req_headers = extra_headers or {}
                        async with session.request(
                            method, url,
                            headers=req_headers,
                            allow_redirects=self.config.follow_redirects,
                            max_redirects=self.config.max_redirects,
                            proxy=self.config.proxy,
                        ) as response:
                            if response.status in retry_handler.retryable_statuses:
                                # Raise so NovaRetryHandler actually retries/backs off,
                                # instead of silently swallowing 429/5xx as a hard failure.
                                stats['requests_retried'] += 1
                                raise RetryableStatusError(response.status)

                            if response.status == 200:
                                stats['requests_successful'] += 1

                                if method == 'HEAD':
                                    return response, None

                                content_length = response.headers.get('Content-Length')
                                if content_length and int(content_length) > self.config.max_js_size:
                                    return None

                                try:
                                    content = await response.text()
                                    content_type = response.headers.get('Content-Type', '')

                                    if url.endswith('.js') and not self.validator.is_valid_js_content(content, content_type):
                                        stats['false_positives_filtered'] += 1
                                        return None

                                    return response, content
                                except Exception:
                                    return None
                            elif response.status == 403 and _retry_as_crawler:
                                # Signal caller to retry once with a crawler UA. Many WAFs
                                # block generic client UAs but allow known search-engine bots.
                                return '__RETRY_403__'
                            else:
                                stats['requests_failed'] += 1
                                return None

                    try:
                        result = await retry_handler.execute(do_request)
                        if result == '__RETRY_403__':
                            crawler_ua = (
                                'Mozilla/5.0 (compatible; Googlebot/2.1; '
                                '+http://www.google.com/bot.html)'
                            )
                            result = await retry_handler.execute(
                                do_request, {'User-Agent': crawler_ua}
                            )
                            if result == '__RETRY_403__':
                                stats['requests_failed'] += 1
                                logger.debug(f"[FETCH-FAIL] {url} -> HTTP 403 (crawler UA also blocked)")
                                return None
                        return result
                    except RetryableStatusError as e:
                        stats['requests_failed'] += 1
                        logger.debug(f"[FETCH-FAIL] {url} -> HTTP {e.status} (exhausted retries)")
                        return None
                    except Exception as e:
                        stats['requests_failed'] += 1
                        logger.debug(f"[FETCH-FAIL] {url} -> {type(e).__name__}: {e}")
                        return None

            def extract_endpoints_from_content(content: str, base_url: str) -> Set[str]:
                """
                Pull endpoint-like references out of JS/HTML content and resolve them
                to full scheme://domain URLs -- including bare absolute paths such as
                "/constructor/main.js" or "/internal/config.json" that don't include
                a domain of their own.
                """
                found = set()

                # 1) Fully-qualified URLs on the target domain
                full_url_pattern = re.compile(
                    r'["\'](https?://' + re.escape(target_domain) + r'/[^"\'\s]{1,})["\']',
                    re.IGNORECASE
                )
                for match in full_url_pattern.findall(content):
                    found.add(match.split('?')[0])

                # 2) Any quoted absolute path (e.g. /constructor/main.js, /api/v1/users,
                #    /internal/config.json) -- resolved with the target's scheme+domain.
                #    This is what previously only matched a narrow /api|/v\d|/graphql|... allowlist.
                path_pattern = re.compile(r'["\'](/[a-zA-Z0-9_][a-zA-Z0-9_\-./]{1,200})["\']')
                for match in path_pattern.findall(content):
                    # Skip obvious non-endpoints (fragment-only, protocol-relative already handled)
                    if match.startswith('//'):
                        continue
                    resolved = resolve_url(match, base_url)
                    if resolved:
                        found.add(resolved.split('?')[0])

                return found

            def extract_js_urls_from_content(content: str, base_url: str) -> Set[str]:
                """
                Find EVERY reference to a .js file in the given content, no
                matter how it's written -- full URL, protocol-relative,
                absolute path ("/car/main.js"), relative path
                ("car/main.js", "./chunk.js", "../lib/x.js"), or a bare
                filename -- and resolve every single one to a full,
                absolute URL. Deliberately overlaps with import/require
                pattern matching and <script src> parsing elsewhere; sets
                de-duplicate, and the goal is not missing a JS reference
                just because a given site happens to write it as a plain
                object value or route-map string instead of a proper
                import/require statement.
                """
                found = set()
                # Any quoted string ending in .js (optionally followed by a
                # query string or fragment), 1-300 chars, no embedded
                # whitespace/quotes. Covers all reference styles above --
                # resolve_url() figures out absolute vs relative vs full URL.
                pattern = re.compile(
                    r'["\']([^"\'\s]{1,300}?\.js)(?:[?#][^"\']*)?["\']',
                    re.IGNORECASE
                )
                for match in pattern.findall(content):
                    match = match.strip()
                    if not match or match.startswith(('data:', 'javascript:', 'blob:', 'mailto:')):
                        continue
                    resolved = resolve_url(match, base_url)
                    if resolved and self.validator.is_valid_js_url(resolved):
                        found.add(resolved.split('?')[0])
                return found

            async def process_js(js_url: str, source: str):
                if js_url in js_files or js_url in in_flight:
                    return

                if len(js_files) >= self.config.max_js_files:
                    return

                if not self.validator.is_valid_js_url(js_url):
                    return

                # Reserve BEFORE awaiting -- js_files only gets its entry
                # once the fetch below completes, so without this a second
                # concurrent chain referencing the same URL could pass the
                # check above and start its own duplicate fetch.
                in_flight.add(js_url)

                result = await fetch(js_url)
                if not result:
                    return

                response, content = result

                js_file = JSFile(
                    url=js_url,
                    source=source,
                    status_code=response.status,
                    content_type=response.headers.get('Content-Type', ''),
                    size=len(content) if content else 0,
                    content_hash=hashlib.md5(content.encode()).hexdigest() if content else None,
                )

                js_files[js_url] = js_file
                stats['js_files_found'] += 1
                live_append(live_js_path, js_url)

                if not self.config.quiet:
                    logger.info(f"  {Fore.GREEN}[JS]{Style.RESET_ALL} {js_url}")

                if self.config.deep_analysis and content:
                    stats['js_analyzed'] += 1
                    new_js, new_endpoints, new_secrets = self._extract_from_js(
                        content, js_url, target_domain, target_scheme,
                        extract_endpoints_from_content, extract_js_urls_from_content
                    )

                    js_file.endpoints = new_endpoints
                    js_file.secrets = new_secrets

                    newly_seen_endpoints = new_endpoints - endpoints
                    newly_seen_secrets = new_secrets - secrets
                    endpoints.update(new_endpoints)
                    secrets.update(new_secrets)
                    for ep in newly_seen_endpoints:
                        live_append(live_endpoints_path, ep)
                    for sec in newly_seen_secrets:
                        live_append(live_secrets_path, sec)

                    stats['endpoints_discovered'] = len(endpoints)
                    stats['secrets_found'] = len(secrets)

                    if self.config.follow_js_chains:
                        chain_targets = [u for u in new_js if u not in js_files]
                        # Run chained JS discovery concurrently instead of one at a time
                        await asyncio.gather(*[process_js(u, f"chain:{js_url}") for u in chain_targets])

            async def crawl(url: str, depth: int = 0):
                if depth > self.config.max_depth:
                    return

                if url in crawled_urls:
                    return

                if len(crawled_urls) >= self.config.max_pages:
                    return

                crawled_urls.add(url)
                stats['pages_crawled'] += 1

                if not self.config.quiet:
                    logger.info(f"  {Fore.CYAN}[CRAWL]{Style.RESET_ALL} Depth {depth} | {url}")

                result = await fetch(url)
                if not result:
                    return

                _, html = result
                if not html:
                    return

                soup = BeautifulSoup(html, 'html.parser')

                script_targets = set()
                for script in soup.find_all('script', src=True):
                    resolved = resolve_url(script['src'], url)
                    if resolved and self.validator.is_valid_js_url(resolved):
                        script_targets.add(resolved)

                # Also scan the raw HTML for any .js reference the strict
                # <script src> parse would miss -- inline scripts building
                # a URL from a string, JSON config blobs embedded in the
                # page, data-* attributes, etc.
                script_targets.update(extract_js_urls_from_content(html, url))

                # JS files on a page are independent -- fetch/analyze them concurrently
                await asyncio.gather(*[process_js(u, f"page:{url}") for u in script_targets])

                if depth < self.config.max_depth:
                    links = set()
                    for a in soup.find_all('a', href=True):
                        resolved = resolve_url(a['href'], url)
                        if resolved and target_domain in resolved:
                            skip = {'.jpg', '.png', '.gif', '.css', '.js', '.pdf', '.zip', '.mp4'}
                            if not any(resolved.lower().endswith(ext) for ext in skip):
                                links.add(resolved)

                    link_list = list(links)
                    if len(link_list) > self.config.max_links_per_page:
                        if not self.config.quiet:
                            logger.warning(
                                f"  {Fore.YELLOW}[LINKS]{Style.RESET_ALL} {url} has "
                                f"{len(link_list)} links, capping at {self.config.max_links_per_page} "
                                f"(raise --max-links-per-page to increase)"
                            )
                        link_list = link_list[:self.config.max_links_per_page]

                    # Concurrent crawling instead of sequential await-in-a-loop
                    await asyncio.gather(*[crawl(link, depth + 1) for link in link_list])

            async def brute_force():
                common_paths = [
                    'js/main.js', 'js/app.js', 'js/bundle.js',
                    'static/js/main.js', 'assets/js/main.js',
                    'dist/bundle.js', 'build/main.js',
                    'js/vendor.js', 'js/chunk-vendors.js',
                    'js/config.js', 'js/settings.js',
                ]

                sem = asyncio.Semaphore(10)
                # Always build from the domain root explicitly, not
                # urljoin(target_url, path) -- if target_url is itself a
                # JS file (e.g. https://site.com/static/bundle.js),
                # urljoin resolves relative to that file's directory
                # ("static/js/main.js") instead of the intended domain
                # root ("js/main.js").
                root = f"{target_scheme}://{target_domain}"

                async def check_path(path: str):
                    async with sem:
                        url = f"{root}/{path}"
                        if url not in js_files:
                            result = await fetch(url, method='HEAD')
                            if result:
                                await process_js(url, f"brute:{path}")

                await asyncio.gather(*[check_path(p) for p in common_paths])

            async def passive_enumeration():
                """
                Query external sources for known JS URLs on this domain. Restores the
                capability from the earlier prototype, gated by --no-passive.
                """
                sources = {
                    'wayback': (
                        f"https://web.archive.org/cdx/search/cdx?url=*.{target_domain}/*"
                        f"&output=json&fl=original&collapse=urlkey&filter=statuscode:200&limit=5000"
                    ),
                    'urlscan': f"https://urlscan.io/api/v1/search/?q=domain:{target_domain}&size=1000",
                }

                for source_name, source_url in sources.items():
                    try:
                        result = await fetch(source_url)
                        if not result:
                            continue
                        _, content = result
                        if not content:
                            continue

                        found_urls = re.findall(r'https?://[^\s"\']+\.js[^\s"\']*', content)
                        for u in found_urls:
                            if target_domain not in u:
                                continue
                            cleaned = u.split('?')[0]
                            if self.validator.is_valid_js_url(cleaned) and cleaned not in js_files:
                                stats['passive_hits'] += 1
                                await process_js(cleaned, f"passive:{source_name}")
                    except Exception:
                        continue

            try:
                if self.config.passive_scan:
                    await passive_enumeration()

                if self.config.brute_force:
                    await brute_force()

                # Dispatch every raw target that was grouped under this
                # domain. Each one is either a direct JS file URL (e.g.
                # -u https://site.com/app.js -- crawling it as HTML would
                # silently find nothing, since BeautifulSoup parsing raw
                # JS finds zero <script src> tags and zero <a href>
                # links) or a webpage to crawl normally. All of them feed
                # into the SAME shared js_files/endpoints/secrets state
                # for this domain, run concurrently.
                js_file_targets = [u for u in target_urls if self.validator.is_valid_js_url(u)]
                page_targets = [u for u in target_urls if u not in js_file_targets]

                if js_file_targets and not self.config.quiet:
                    logger.info(
                        f"  {Fore.CYAN}[MODE]{Style.RESET_ALL} "
                        f"{len(js_file_targets)} direct JS file target(s) for {target_domain} "
                        f"-- processing as JS, not crawling as HTML"
                    )

                await asyncio.gather(
                    *[process_js(u, "direct-target") for u in js_file_targets],
                    *[crawl(u, 0) for u in page_targets],
                )

                result.success = True

            except Exception as e:
                logger.error(f"  {Fore.RED}[ERROR]{Style.RESET_ALL} {target_domain}: {e}")
                result.error = str(e)
                result.success = False

        result.js_files = js_files
        result.endpoints = endpoints
        result.secrets = secrets
        result.stats = stats
        result.end_time = datetime.now()

        return result

    def _extract_from_js(
        self,
        js_content: str,
        js_url: str,
        target_domain: str,
        target_scheme: str,
        extract_endpoints_from_content,
        extract_js_urls_from_content,
    ) -> Tuple[Set[str], Set[str], Set[str]]:
        """Extract JS files, endpoints, and secrets from JavaScript content"""
        new_js = set()
        endpoints = set()
        secrets = set()

        # Comprehensive JS-reference discovery -- catches every form a .js
        # file can be referenced in: proper import/require statements,
        # absolute paths ("/car/main.js"), relative paths ("car/main.js",
        # "./chunk.js", "../lib/x.js"), protocol-relative and full URLs,
        # and bare filenames used as plain object/string values (route
        # maps, lazy-load tables, etc). Every match is resolved to a full,
        # absolute URL regardless of how it was originally written.
        new_js.update(extract_js_urls_from_content(js_content, js_url))

        # Non-.js endpoints (API paths, config files, etc). Any .js-looking
        # path this also happens to catch gets folded into new_js instead
        # of endpoints -- it's a JS file, not a generic endpoint.
        if self.config.extract_endpoints:
            for item in extract_endpoints_from_content(js_content, js_url):
                if self.validator.is_valid_js_url(item):
                    new_js.add(item.split('?')[0])
                else:
                    endpoints.add(item)

        if self.config.extract_secrets:
            secret_pattern = re.compile(
                r'(?:api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token|bearer|jwt|secret)\s*[:=]\s*["\']([^"\'\s]{16,})["\']',
                re.IGNORECASE
            )
            for match in secret_pattern.findall(js_content):
                secrets.add(match)

        return new_js, endpoints, secrets

    async def run(self):
        self.global_stats['start_time'] = datetime.now()

        NovaBanner.display(self.config)

        # Group raw targets by domain -- a "target" from the user's
        # perspective can be a URL, bare domain, or JS file, and a batch
        # can legitimately contain several of these for the SAME host
        # (e.g. a list of JS file URLs discovered elsewhere, all on one
        # site). Without this grouping, each one got its own directory
        # keyed only by domain name, so concurrent same-domain targets
        # raced to truncate/overwrite each other's live output files.
        # Grouping means one host = one output directory = one merged,
        # correct result, regardless of how many individual targets (or
        # what mix of pages vs JS files) point at it.
        domain_groups: "OrderedDict[str, List[str]]" = OrderedDict()
        for t in self.config.target_urls:
            d = urlparse(t).netloc
            domain_groups.setdefault(d, []).append(t)

        self.global_stats['total_targets'] = len(domain_groups)
        self.global_stats['total_inputs'] = len(self.config.target_urls)

        # Compute the output location ONCE, up front, so every target writes
        # to the same scan folder as it completes -- not only at the very
        # end of the whole batch.
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_base = os.path.join(self.config.output_dir, f'nova_scan_{timestamp}')
        os.makedirs(self.output_base, exist_ok=True)

        sem = asyncio.Semaphore(self.config.concurrent_targets)

        async def process_with_limit(domain: str, urls_for_domain: List[str]):
            async with sem:
                if len(urls_for_domain) > 1:
                    logger.info(
                        f"{Fore.MAGENTA}[TARGET]{Style.RESET_ALL} Starting: {domain} "
                        f"({len(urls_for_domain)} inputs merged)"
                    )
                else:
                    logger.info(f"{Fore.MAGENTA}[TARGET]{Style.RESET_ALL} Starting: {urls_for_domain[0]}")

                safe_domain = domain.replace(':', '_').replace('.', '_') or f"target_{abs(hash(tuple(urls_for_domain)))}"
                target_dir = os.path.join(self.output_base, safe_domain)

                try:
                    result = await self.process_target(urls_for_domain, domain, target_dir)
                except Exception as e:
                    # A bug or unexpected failure on ONE domain must not take
                    # down the whole batch or lose results already saved for
                    # other domains. Live-written js_files.txt/endpoints.txt
                    # for THIS domain still exist on disk even if we land
                    # here mid-scan.
                    logger.error(f"  {Fore.RED}[CRASH]{Style.RESET_ALL} {domain}: {e}")
                    result = TargetResult(
                        target_url=urls_for_domain[0],
                        domain=domain,
                        all_targets=urls_for_domain,
                        start_time=datetime.now(),
                        end_time=datetime.now(),
                        success=False,
                        error=str(e),
                    )

                self.all_results[domain] = result

                # Save this domain's final consolidated report NOW, right as
                # it finishes -- do not wait for every other domain in the
                # batch to also finish first.
                self._save_target_result(result, target_dir)

                if result.success:
                    self.global_stats['successful_targets'] += 1
                    self.global_stats['total_js_files'] += result.stats.get('js_files_found', 0)
                    self.global_stats['total_endpoints'] += result.stats.get('endpoints_discovered', 0)
                    self.global_stats['total_secrets'] += result.stats.get('secrets_found', 0)

                    duration = (result.end_time - result.start_time).total_seconds()
                    logger.info(
                        f"{Fore.GREEN}[DONE]{Style.RESET_ALL} {domain} | "
                        f"JS: {result.stats.get('js_files_found', 0)} | "
                        f"Endpoints: {result.stats.get('endpoints_discovered', 0)} | "
                        f"Secrets: {result.stats.get('secrets_found', 0)} | "
                        f"Duration: {duration:.1f}s"
                    )
                else:
                    self.global_stats['failed_targets'] += 1
                    logger.error(f"{Fore.RED}[FAIL]{Style.RESET_ALL} {domain}: {result.error}")

                return result

        try:
            tasks = [process_with_limit(d, urls) for d, urls in domain_groups.items()]
            await asyncio.gather(*tasks)
        finally:
            # Runs even on KeyboardInterrupt/CancelledError -- whatever
            # targets finished (and were already saved above as they
            # completed) still get a summary written rather than losing
            # everything because the run didn't reach a clean finish.
            self.global_stats['end_time'] = datetime.now()
            self._save_global_summary()
            self._print_final_summary()

    def _save_target_result(self, result: TargetResult, target_dir: str):
        """
        Write the final, deduplicated, sorted version of one target's
        results. This runs as soon as THAT target finishes (see run()),
        not after the whole batch completes. The live-appended files written
        during the scan (see process_target/live_append) already guarantee
        nothing is lost even if the process is killed before this point --
        this just replaces them with a clean final copy plus the JSON report.
        """
        try:
            os.makedirs(target_dir, exist_ok=True)

            if result.js_files:
                with open(os.path.join(target_dir, 'js_files.txt'), 'w') as f:
                    for url in sorted(result.js_files.keys()):
                        f.write(f"{url}\n")

            if result.endpoints:
                with open(os.path.join(target_dir, 'endpoints.txt'), 'w') as f:
                    for endpoint in sorted(result.endpoints):
                        f.write(f"{endpoint}\n")

            if result.secrets:
                with open(os.path.join(target_dir, 'secrets.txt'), 'w') as f:
                    for secret in sorted(result.secrets):
                        f.write(f"{secret}\n")

            target_report = {
                'target': result.target_url,
                'all_targets': result.all_targets,
                'domain': result.domain,
                'success': result.success,
                'error': result.error,
                'duration': (result.end_time - result.start_time).total_seconds() if result.end_time and result.start_time else 0,
                'statistics': result.stats,
                'js_files_count': len(result.js_files),
                'endpoints_count': len(result.endpoints),
                'secrets_count': len(result.secrets),
            }

            with open(os.path.join(target_dir, 'report.json'), 'w') as f:
                json.dump(target_report, f, indent=2, default=str)

            if not self.config.quiet:
                logger.info(f"  {Fore.GREEN}[SAVED]{Style.RESET_ALL} {target_dir}")

        except Exception as e:
            # Saving must never silently no-op -- if this fails, say so,
            # since it means the scan's findings are at risk of being lost.
            logger.error(f"  {Fore.RED}[SAVE-ERROR]{Style.RESET_ALL} Could not write results for {result.target_url}: {e}")

    def _save_global_summary(self):
        output_base = getattr(self, 'output_base', None)
        if not output_base:
            # Defensive fallback -- should not happen since run() sets this
            # before any target starts, but never silently drop the summary.
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_base = os.path.join(self.config.output_dir, f'nova_scan_{timestamp}')
            os.makedirs(output_base, exist_ok=True)
        else:
            timestamp = os.path.basename(output_base).replace('nova_scan_', '')

        if self.config.merge_results:
            all_js = set()
            all_endpoints = set()
            all_secrets = set()

            for result in self.all_results.values():
                all_js.update(result.js_files.keys())
                all_endpoints.update(result.endpoints)
                all_secrets.update(result.secrets)

            with open(os.path.join(output_base, 'all_js_files.txt'), 'w') as f:
                for url in sorted(all_js):
                    f.write(f"{url}\n")

            if all_endpoints:
                with open(os.path.join(output_base, 'all_endpoints.txt'), 'w') as f:
                    for endpoint in sorted(all_endpoints):
                        f.write(f"{endpoint}\n")

            if all_secrets:
                with open(os.path.join(output_base, 'all_secrets.txt'), 'w') as f:
                    for secret in sorted(all_secrets):
                        f.write(f"{secret}\n")

        summary = {
            'scan_info': {
                'timestamp': timestamp,
                'mode': self.config.mode.value,
                'total_targets': self.global_stats['total_targets'],
                'successful': self.global_stats['successful_targets'],
                'failed': self.global_stats['failed_targets'],
                'duration': (self.global_stats['end_time'] - self.global_stats['start_time']).total_seconds(),
            },
            'global_stats': self.global_stats,
            'targets': {
                domain: {
                    'all_targets': result.all_targets,
                    'success': result.success,
                    'js_files': len(result.js_files),
                    'endpoints': len(result.endpoints),
                    'secrets': len(result.secrets),
                    'stats': result.stats,
                }
                for domain, result in self.all_results.items()
            }
        }

        with open(os.path.join(output_base, 'summary.json'), 'w') as f:
            # default=str converts start_time/end_time datetimes (and anything
            # else non-JSON-native) to strings instead of crashing the whole
            # run at the very last step after all the scanning work is done.
            json.dump(summary, f, indent=2, default=str)

        logger.info(f"\n{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
        logger.info(f"{Fore.GREEN}[SAVED] Results: {output_base}{Style.RESET_ALL}")
        logger.info(f"  • Per-target directories with js_files.txt, endpoints.txt")
        logger.info(f"  • summary.json - Global scan summary")
        if self.config.merge_results:
            logger.info(f"  • all_js_files.txt - Merged JS files")
            logger.info(f"  • all_endpoints.txt - Merged endpoints")

    def _print_final_summary(self):
        elapsed = (self.global_stats['end_time'] - self.global_stats['start_time']).total_seconds()

        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*70}")
        print(f"  NOVA BATCH SCAN COMPLETE")
        print(f"{'='*70}{Style.RESET_ALL}\n")

        print(f"{Fore.YELLOW}Global Statistics:{Style.RESET_ALL}")
        print(f"  Total Duration: {elapsed:.1f} seconds")
        print(f"  Targets: {self.global_stats['total_targets']} ({Fore.GREEN}{self.global_stats['successful_targets']} success{Style.RESET_ALL}, {Fore.RED}{self.global_stats['failed_targets']} failed{Style.RESET_ALL})")
        print(f"  Total JS Files: {Fore.GREEN}{self.global_stats['total_js_files']}{Style.RESET_ALL}")
        print(f"  Total Endpoints: {Fore.GREEN}{self.global_stats['total_endpoints']}{Style.RESET_ALL}")
        print(f"  Total Secrets: {Fore.RED}{self.global_stats['total_secrets']}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}Per-Target Results:{Style.RESET_ALL}")
        print(f"  {'Target':<40} {'JS':<6} {'Endpoints':<10} {'Secrets':<8} {'Status'}")
        print(f"  {'-'*40} {'-'*6} {'-'*10} {'-'*8} {'-'*10}")

        for domain, result in self.all_results.items():
            status = f"{Fore.GREEN}SUCCESS{Style.RESET_ALL}" if result.success else f"{Fore.RED}FAILED{Style.RESET_ALL}"
            print(f"  {domain[:38]:<40} {len(result.js_files):<6} {len(result.endpoints):<10} {len(result.secrets):<8} {status}")

        if self.config.quiet:
            for result in self.all_results.values():
                for js_url in result.js_files.keys():
                    print(js_url)


def main():
    parser = argparse.ArgumentParser(
        description='NOVA - Next-gen Online Vulnerability Analyzer | Pipeline Ready',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f'''
{Fore.CYAN}Pipeline Examples:{Style.RESET_ALL}
  # Single URL
  python nova.py -u https://example.com

  # From stdin (pipe)
  echo "example.com" | python nova.py
  cat domains.txt | python nova.py

  # From file
  python nova.py -f domains.txt

  # Multiple URLs from subfinder/amass
  subfinder -d example.com -silent | python nova.py --mode aggressive

  # Chain with other tools
  cat urls.txt | python nova.py --quiet | tee all_js.txt

  # Process subdomains from file
  python nova.py -f subdomains.txt -t 10 --concurrent 3 --output results/

  # Merge all results into single output
  python nova.py -f targets.txt --merge

  # Stealth scan on multiple domains
  cat domains.txt | python nova.py --mode stealth --rate 2
        ''')
    )

    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument('-u', '--url', help='Single target URL')
    target_group.add_argument('-f', '--file', help='File containing list of URLs/subdomains')

    parser.add_argument('--mode', type=str, choices=['stealth', 'normal', 'aggressive', 'insane'],
                       default='normal', help='Scan intensity mode (default: normal)')

    perf_group = parser.add_argument_group('Performance Tuning')
    perf_group.add_argument('-t', '--threads', type=int, default=10,
                           help='Threads per target (default: 10)')
    perf_group.add_argument('--concurrent', type=int, default=3,
                           help='Concurrent targets (default: 3)')
    perf_group.add_argument('-d', '--depth', type=int, default=3,
                           help='Crawl depth (default: 3)')
    perf_group.add_argument('--timeout', type=int, default=30,
                           help='Request timeout in seconds (default: 30)')
    perf_group.add_argument('--rate', type=float, default=0.1,
                           help='Rate limit in seconds (default: 0.1)')
    perf_group.add_argument('--max-links-per-page', type=int, default=200,
                           help='Max outbound links followed per page (default: 200)')

    retry_group = parser.add_argument_group('Retry Configuration')
    retry_group.add_argument('--retries', type=int, default=3,
                            help='Max retries (default: 3)')
    retry_group.add_argument('--retry-delay', type=float, default=1.0,
                            help='Base retry delay (default: 1.0)')

    conn_group = parser.add_argument_group('Connection Options')
    conn_group.add_argument('--proxy', help='Proxy URL')
    conn_group.add_argument('--verify-ssl', action='store_true',
                           help='Enable SSL verification')
    conn_group.add_argument('--no-redirects', action='store_true',
                           help='Disable redirects')

    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('-c', '--cookie', help='Cookie string')
    auth_group.add_argument('-H', '--header', action='append',
                           help='Custom header (repeatable)')
    auth_group.add_argument('--user-agent', help='Custom User-Agent')

    features_group = parser.add_argument_group('Feature Toggles')
    features_group.add_argument('--no-passive', action='store_true',
                               help='Disable passive scanning (Wayback/urlscan)')
    features_group.add_argument('--no-brute', action='store_true',
                               help='Disable brute forcing')
    features_group.add_argument('--no-deep', action='store_true',
                               help='Disable deep analysis')
    features_group.add_argument('--no-endpoints', action='store_true',
                               help='Skip endpoint extraction')
    features_group.add_argument('--no-secrets', action='store_true',
                               help='Skip secret detection')
    features_group.add_argument('--no-chain', action='store_true',
                               help='Disable JS chain following')

    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output', default='nova_output',
                             help='Output directory (default: nova_output)')
    output_group.add_argument('--merge', action='store_true',
                             help='Merge all targets into single files')
    output_group.add_argument('--quiet', action='store_true',
                             help='Minimal output (useful for piping)')

    limits_group = parser.add_argument_group('Limits')
    limits_group.add_argument('--max-pages', type=int, default=1000,
                             help='Max pages per target (default: 1000)')
    limits_group.add_argument('--max-js-files', type=int, default=10000,
                             help='Max JS files per target (default: 10000)')

    args = parser.parse_args()

    targets = []

    if args.url:
        targets = [args.url]
    elif args.file:
        targets = TargetLoader.from_file(args.file)
    elif not sys.stdin.isatty():
        targets = TargetLoader.from_stdin()
    else:
        parser.print_help()
        print(f"\n{Fore.RED}[ERROR]{Style.RESET_ALL} No target specified. Use -u, -f, or pipe via stdin")
        sys.exit(1)

    targets = TargetLoader.normalize_targets(targets)

    if not targets:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No valid targets found")
        sys.exit(1)

    mode = ScanMode[args.mode.upper()]

    cookies = {}
    if args.cookie:
        for cookie in args.cookie.split(';'):
            if '=' in cookie:
                k, v = cookie.strip().split('=', 1)
                cookies[k] = v

    headers = {}
    if args.header:
        for header in args.header:
            if ':' in header:
                k, v = header.split(':', 1)
                headers[k.strip()] = v.strip()

    config = NovaConfig(
        target_urls=targets,
        read_from_stdin=not sys.stdin.isatty() and not args.url and not args.file,
        target_file=args.file,
        mode=mode,
        max_threads=args.threads,
        concurrent_targets=args.concurrent,
        max_depth=args.depth,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        rate_limit=args.rate,
        max_pages=args.max_pages,
        max_js_files=args.max_js_files,
        max_links_per_page=args.max_links_per_page,
        verify_ssl=args.verify_ssl,
        follow_redirects=not args.no_redirects,
        proxy=args.proxy,
        cookies=cookies,
        headers=headers,
        # Bare "Mozilla/5.0" with nothing else is a well-known bot-detection
        # signature -- fall through to NovaConfig's realistic full UA string
        # instead of overriding it with a truncated one.
        **({'user_agent': args.user_agent} if args.user_agent else {}),
        passive_scan=not args.no_passive,
        brute_force=not args.no_brute,
        deep_analysis=not args.no_deep,
        extract_endpoints=not args.no_endpoints,
        extract_secrets=not args.no_secrets,
        follow_js_chains=not args.no_chain,
        output_dir=args.output,
        merge_results=args.merge,
        quiet=args.quiet,
    )

    async def main_async():
        nova = NOVA(config)
        await nova.run()

    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] NOVA terminated by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
