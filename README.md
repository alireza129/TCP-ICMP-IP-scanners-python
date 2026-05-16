# TCP-ICMP-IP-scanners-python
Python Batch IP Scanner
A pair of standard-library-only Python scripts for scanning IP lists in batches.

TCP scanner: tests whether each IP accepts a TCP connection on a chosen port using socket.create_connection().

ICMP scanner: sends ICMP echo requests with raw sockets, which generally requires elevated privileges such as root on Unix-like systems or Administrator on Windows.

Both scripts support:

Loading IPs from a .txt file with one IP per line or comma-separated values.

Sequential or randomized scan order, with randomization using random.shuffle().

User-defined batch size and worker count.

Running a chosen number of batches in a row, then prompting again for the next run count.

Per-batch progress bars.

Immediate printing of successful results.

Scripts
Script	Purpose	Success output
tcp_scanner.py	Checks whether an IP accepts a TCP connection on the chosen port.	IP:PORT
icmp_scanner.py	Checks whether an IP replies to ICMP echo requests via raw sockets.	IP
Requirements
Python 3.

No third-party packages; both scripts use only the Python standard library, including socket, pathlib, random, and concurrent.futures.

For the ICMP version, elevated privileges are usually required because raw ICMP sockets are commonly restricted by the operating system.

IP file format
The input file can use either format below because the loader reads the text file, normalizes newlines into commas, then splits and trims values.

One IP per line
text
94.130.13.19
94.130.50.12
198.252.206.1
Comma-separated
text
"94.130.13.19", "94.130.50.12", "198.252.206.1"
TCP scanner usage
Run the TCP scanner:

bash
python3 tcp_scanner.py
It prompts for:

Path to the .txt file.

Scan mode: sequential or randomized.

Batch size.

Worker count.

TCP port to test.

How many batches to run right now, defaulting to 1 when Enter is pressed.

Example session
text
Path to txt file with IPs: ~/ips.txt
Scan mode - sequential or randomized? [s/r, default=r]:
Batch size: 50
Worker count: 50
TCP port to test (example 80, 443, 22): 443
How many batches do you want to do right now? [default=1]:
If Enter is pressed at the last prompt, the script runs one batch, then asks again how many more batches should run next.

What counts as success
A TCP result is marked successful only if the script can establish a TCP connection to the target IP and port with socket.create_connection().

Examples:

203.0.113.10:443 means the TCP connect succeeded on port 443.

A timeout, refusal, or other socket error is treated as not successful for this check.

ICMP scanner usage
Run the ICMP scanner:

bash
python3 icmp_scanner.py
The prompts are the same except there is no port prompt, because ICMP echo is not tied to a TCP or UDP port.

Example session
text
Path to txt file with IPs: ~/ips.txt
Scan mode - sequential or randomized? [s/r, default=r]: r
Batch size: 100
Worker count: 100
How many batches do you want to do right now? [default=1]: 2
What counts as success
An ICMP result is successful when the target replies with an ICMP Echo Reply matching the sent request identifier and sequence number.

Privilege note for ICMP
The ICMP script uses raw sockets through the standard library socket module, and that usually requires elevated privileges on mainstream operating systems.

Typical outcomes:

Linux/macOS: run with sudo if needed.

Windows: run in an Administrator shell if needed.

Without sufficient privileges, the script may raise PermissionError.

How batching works
The scanners process the IP list in slices of the chosen batch size, then ask how many more batches should run next.

Example:

10,000 IPs

Batch size: 50

"How many batches right now?" = 3

That run processes 150 IPs, then prompts again for the next batch-count decision.

Concurrency
Worker count controls the maximum number of concurrent tasks submitted to ThreadPoolExecutor for each batch.

Practical guidance:

Use a worker count close to the batch size for maximum parallelism.

Use a lower worker count if the machine or network becomes overloaded.

Very large worker counts may create extra socket pressure and reduce practical stability depending on OS and network limits.

Randomized vs sequential mode
Sequential scans the IPs in the order they appear in the file.

Randomized shuffles the list in place before scanning begins with random.shuffle().

Randomized mode is useful when the source list has clustered address ranges and a more mixed sampling order is preferred.

Troubleshooting
TCP scanner shows no successes
Possible causes:

The chosen port is closed on most targets.

A firewall drops connection attempts.

The timeout is too short for the path latency.

The worker count is too high for the environment, causing local resource pressure.

ICMP scanner exits with a permission error
This usually means the operating system blocked raw socket creation without elevated privileges.

File load fails
Check that:

The provided path exists.

The file is readable.

The IPs are separated by newlines or commas in plain text.

Suggested filenames
text
tcp_scanner.py
icmp_scanner.py
README.md
ips.txt
Safety note
Use these scripts only on systems and networks that are owned, authorized, or explicitly permitted for testing. Raw ICMP and large parallel TCP connection attempts can trigger monitoring or rate-limiting on managed networks.
