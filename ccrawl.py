#!/usr/bin/env python3

import argparse
import sys
import threading
import time
import queue
import logging
import requests
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode
from bs4 import BeautifulSoup
import csv
import json
import yaml
import xml.etree.ElementTree as ET
import os
import tldextract

# Global variables for tracking visited URLs and robots.txt rules
visited_urls = set()
lock = threading.Lock()
output_lock = threading.Lock()
header_written = False  # Initialize header_written at module level


def normalize_url(url):
    """Normalize URL by removing fragments and sorting query parameters."""
    if not urlparse(url).scheme:
        url = 'https://' + url  # Default to HTTPS
    parsed = urlparse(url)
    # Remove fragment
    parsed = parsed._replace(fragment='')
    # Sort query parameters
    query = urlencode(sorted(parse_qsl(parsed.query)))
    parsed = parsed._replace(query=query)
    return urlunparse(parsed)


def get_registered_domain(url):
    """Extract the registered domain from a URL."""
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}"


def is_same_domain(start_domain, url):
    """Check if the URL is within the same registered domain."""
    url_domain = get_registered_domain(url)
    return url_domain == start_domain


def get_robots_parser(base_url, user_agent):
    """Retrieve and parse the robots.txt file."""
    robots_url = urljoin(base_url, '/robots.txt')
    try:
        rp = requests.get(robots_url, headers={'User-Agent': user_agent}, timeout=10)
        if rp.status_code == 200:
            lines = rp.text.splitlines()
        else:
            lines = []
    except Exception as e:
        logging.error(f"Error fetching robots.txt: {e}")
        lines = []

    parser = RobotsTxtParser(user_agent)
    parser.parse(lines)
    return parser


class RobotsTxtParser:
    """Simple robots.txt parser."""
    def __init__(self, user_agent):
        self.user_agent = user_agent
        self.rules = []
        self.crawl_delay = None

    def parse(self, lines):
        ua = None
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.lower().startswith('user-agent:'):
                ua = line.split(':', 1)[1].strip()
            elif ua == '*' or ua == self.user_agent:
                if line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    self.rules.append(path)
                elif line.lower().startswith('crawl-delay:'):
                    delay = line.split(':', 1)[1].strip()
                    try:
                        self.crawl_delay = float(delay)
                    except ValueError:
                        pass

    def can_fetch(self, url):
        parsed = urlparse(url)
        path = parsed.path or '/'
        for rule in self.rules:
            if path.startswith(rule):
                return False
        return True


def output_result(result, args):
    """Output result to console or file with thread safety."""
    global header_written
    with output_lock:
        if args.output_file:
            mode = 'a' if os.path.exists(args.output_file) else 'w'
        else:
            mode = 'a'  # Mode is irrelevant for sys.stdout

        if args.format == 'csv':
            fieldnames = ['url', 'status_code', 'referrer']
            if args.output_file:
                with open(args.output_file, mode, newline='', encoding='utf-8') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    if not header_written:
                        writer.writeheader()
                        header_written = True
                    writer.writerow(result)
            else:
                writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
                if not header_written:
                    writer.writeheader()
                    header_written = True
                writer.writerow(result)
        elif args.format == 'json':
            if args.output_file:
                mode = 'a' if os.path.exists(args.output_file) else 'w'
                with open(args.output_file, mode, encoding='utf-8') as jsonfile:
                    if not header_written:
                        jsonfile.write('[\n')
                        header_written = True
                    else:
                        jsonfile.write(',\n')
                    json.dump(result, jsonfile, indent=2)
            else:
                if not header_written:
                    print('[\n', end='')
                    header_written = True
                else:
                    print(',\n', end='')
                print(json.dumps(result, indent=2), end='')
        elif args.format == 'yaml':
            output_data = yaml.dump([result])
            if args.output_file:
                with open(args.output_file, mode, encoding='utf-8') as yamlfile:
                    yamlfile.write(output_data)
            else:
                print(output_data, end='')
        elif args.format == 'xml':
            url_element = ET.Element('url')
            for key, value in result.items():
                child = ET.SubElement(url_element, key)
                child.text = str(value)
            xml_str = ET.tostring(url_element, encoding='utf-8').decode('utf-8')
            if args.output_file:
                mode = 'a' if os.path.exists(args.output_file) else 'w'
                with open(args.output_file, mode, encoding='utf-8') as xmlfile:
                    if not header_written:
                        xmlfile.write('<?xml version="1.0" encoding="UTF-8"?>\n<results>\n')
                        header_written = True
                    xmlfile.write(xml_str + '\n')
            else:
                if not header_written:
                    print('<?xml version="1.0" encoding="UTF-8"?>\n<results>')
                    header_written = True
                print(xml_str)
        elif args.format == 'md':
            header = '| URL | Status Code | Referrer |\n|-----|-------------|----------|\n'
            line = f"| {result['url']} | {result['status_code']} | {result['referrer']} |\n"
            if args.output_file:
                with open(args.output_file, mode, encoding='utf-8') as mdfile:
                    if not header_written:
                        mdfile.write(header)
                        header_written = True
                    mdfile.write(line)
            else:
                if not header_written:
                    print(header, end='')
                    header_written = True
                print(line, end='')


def crawl_url(url, referrer, depth, args, base_domain, robots_parser):
    """Crawl a single URL and extract links."""
    with lock:
        if url in visited_urls:
            logging.debug(f"Already visited: {url}")
            return
        visited_urls.add(url)
        if args.verbose:
            logging.info(f"Crawling URL: {url} at depth {depth}")

    # Check robots.txt
    if not robots_parser.can_fetch(url):
        logging.warning(f"Disallowed by robots.txt: {url}")
        result = {
            'url': url,
            'status_code': 'Disallowed by robots.txt',
            'referrer': referrer
        }
        output_result(result, args)
        return

    try:
        retries = args.retry
        while retries >= 0:
            try:
                response = requests.get(
                    url,
                    headers={'User-Agent': args.user_agent},
                    timeout=args.connect_timeout
                )
                status_code = response.status_code

                # Handle 429 Too Many Requests
                if status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 1))
                    logging.warning(f"Received 429 for {url}, retrying after {retry_after} seconds")
                    time.sleep(retry_after)
                    raise requests.exceptions.RetryError("429 Too Many Requests")
                break
            except (requests.exceptions.RequestException, requests.exceptions.RetryError) as e:
                retries -= 1
                if retries < 0 or (time.time() - args.start_time) > args.retry_max_time:
                    logging.error(f"Failed to crawl {url}: {e}")
                    status_code = f"Error: {e}"
                    break
                logging.warning(f"Retrying {url}, {retries} retries left")
                time.sleep(args.retry_delay)

        result = {
            'url': url,
            'status_code': status_code,
            'referrer': referrer
        }
        output_result(result, args)

        # Only proceed if the content is HTML, status code is 200, and depth limit not reached
        if (depth < args.depth and
            status_code == 200 and
            'text/html' in response.headers.get('Content-Type', '')):
            soup = BeautifulSoup(response.text, 'html.parser')
            links = set()
            for link_tag in soup.find_all('a', href=True):
                link = urljoin(url, link_tag['href'])
                link = normalize_url(link)
                if is_same_domain(base_domain, link):
                    with lock:
                        if link not in visited_urls:
                            links.add((link, url, depth + 1))
            if args.verbose:
                logging.info(f"Found {len(links)} links on {url}")
            # Add new URLs to the queue
            for link, ref, new_depth in links:
                args.url_queue.put((link, ref, new_depth))
        time.sleep(args.crawl_delay)
    except Exception as e:
        logging.error(f"Error crawling {url}: {e}")
        result = {
            'url': url,
            'status_code': f"Error: {e}",
            'referrer': referrer
        }
        output_result(result, args)


def worker(args, base_domain, robots_parser):
    while True:
        try:
            url, referrer, depth = args.url_queue.get_nowait()
            crawl_url(url, referrer, depth, args, base_domain, robots_parser)
            args.url_queue.task_done()
        except queue.Empty:
            break


def main():
    parser = argparse.ArgumentParser(description='Web crawler that emulates curl.')
    parser.add_argument('url', help='The starting URL to crawl.')
    parser.add_argument('-A', '--user-agent', default='ccrawl/0.1a', help='Specify the User-Agent string.')
    parser.add_argument('-o', '--output-file', help='Write output to <file> instead of stdout.')
    parser.add_argument('--connect-timeout', type=int, default=5, help='Maximum time allowed for connection.')
    parser.add_argument('--max-time', type=int, default=10, help='Maximum time allowed for the transfer.')
    parser.add_argument('--retry', type=int, default=0, help='Number of retries on failed requests.')
    parser.add_argument('--retry-delay', type=int, default=0, help='Delay between retries.')
    parser.add_argument('--retry-max-time', type=int, default=40, help='Maximum time allowed for retries.')
    parser.add_argument('--depth', type=int, default=5, help='Maximum crawl depth.')
    parser.add_argument('--concurrency', type=int, default=1, help='Number of concurrent threads.')
    parser.add_argument('--format', choices=['csv', 'json', 'yaml', 'xml', 'md'], default='csv', help='Output format.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output.')
    args = parser.parse_args()

    # Set logging level based on verbosity
    if args.verbose:
        logging_level = logging.INFO
    else:
        logging_level = logging.WARNING

    logging.getLogger().setLevel(logging_level)

    # Initialize queue and threading
    args.url_queue = queue.Queue()
    args.url_queue.put((normalize_url(args.url), 'N/A', 0))  # Depth starts at 0

    base_domain = get_registered_domain(args.url)

    # Initialize robots.txt parser
    robots_parser = get_robots_parser(args.url, args.user_agent)
    args.crawl_delay = robots_parser.crawl_delay or 1

    args.start_time = time.time()

    # Remove existing output file if any
    if args.output_file and os.path.exists(args.output_file):
        os.remove(args.output_file)

    # Start crawling
    threads = []
    for _ in range(args.concurrency):
        t = threading.Thread(target=worker, args=(args, base_domain, robots_parser))
        t.start()
        threads.append(t)

    try:
        # Wait for all threads to finish
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        logging.warning("Crawler interrupted by user")
        sys.exit(0)
    finally:
        # For JSON and XML formats, close the array or root element if necessary
        if args.format == 'json':
            if args.output_file:
                with open(args.output_file, 'a', encoding='utf-8') as jsonfile:
                    jsonfile.write('\n]')
            else:
                print('\n]')
        elif args.format == 'xml':
            if args.output_file:
                with open(args.output_file, 'a', encoding='utf-8') as xmlfile:
                    xmlfile.write('</results>\n')
            else:
                print('</results>')


if __name__ == '__main__':
    main()

