# ccrawl

`ccrawl` is a Python-based web crawler that emulates `curl` command-line options for HTTP transactions. It is designed to crawl websites responsibly by respecting `robots.txt` rules, handling `429 Too Many Requests` responses, and following polite crawling practices.

## Features

- Supports HTTP and HTTPS protocols.
- Respects `robots.txt` directives and `Crawl-delay`.
- Handles `429 Too Many Requests` by backing off and retrying.
- Outputs crawled URLs, HTTP status codes, and referrers.
- Supports output formats: CSV (default), JSON, YAML, XML, and Markdown.
- Allows customization of User-Agent string.
- Limits crawling to the specified domain.
- Supports command-line options similar to `curl`.

## Installation

### Prerequisites

- Python 3.x
- `git` (if cloning the repository)

### Clone the Repository

```bash
git clone https://github.com/cyberscribe/ccrawl.git
cd ccrawl
```

### Set Up Virtual Environment and Install Dependencies

```bash
chmod +x ccrawl.sh
./ccrawl.sh --help
```

### Usage

ccrawl.sh [options] <url>

**Command-Line Options**

 * <URL>: The starting URL to crawl.
 * -A, --user-agent: Specify the User-Agent string. Default is "ccrawl/0.1a".
 * -o, --output-file: Write output to <file> instead of stdout.
 * --connect-timeout: Maximum time allowed for connection (in seconds). Default is 5.
 * --max-time: Maximum time allowed for the transfer (in seconds). Default is 10.
 * --retry: Number of retries on failed requests. Default is 0.
 * --retry-delay: Delay between retries (in seconds). Default is 0.
 * --retry-max-time: Maximum time allowed for retries (in seconds). Default is 40.
 * --depth: Maximum crawl depth. Default is 5.
 * --concurrency: Number of concurrent threads. Default is 1.
 * --format: Output format. Choices are csv, json, yaml, xml, md. Default is csv.
 * --help: Show help message and exit.

