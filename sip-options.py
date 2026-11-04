import asyncio
import socket
import ssl
import time
import uuid
import sys
import argparse
import signal
import statistics

###
'''
# Sends SIP options over UDP, TCP or TLS to an endpoint and shows DNS resolution time, round-trip-time and packet loss percentage.
# //SHAL 2026
###
'''

# Define the SIP port
SIP_PORT = 5060
SIP_TLS_PORT = 5061

# Request interval, time to wait between requests
REQUEST_INTERVAL = 1

# Percentiles are only printed with at least this many replies (meaningless on tiny samples)
PERCENTILE_MIN_SAMPLES = 20

# Exit codes for use in monitoring
EXIT_OK = 0       # every request got a reply
EXIT_LOSS = 1     # at least one request got no reply
EXIT_ERROR = 2    # could not run: bad arguments, DNS failure, socket error

# One Call-ID for the whole run; CSeq increments per request (RFC 3261 style keepalive)
CALL_ID = str(uuid.uuid4())


# SIP OPTIONS request template
OPTIONS_TEMPLATE = (
    "OPTIONS sip:{server}:{port} SIP/2.0\r\n"
    "Via: SIP/2.0/{via} {lan_ip}:{lan_port};branch=z9hG4bK{branch};rport\r\n"
    "Max-Forwards: 70\r\n"
    "To: <sip:ping@{server}:{port}>\r\n"
    "From: <sip:ping@{server}:{port}>;tag=73686572617A\r\n"
    "Call-ID: {call_id}\r\n"
    "CSeq: {cseq} OPTIONS\r\n"
    "Contact: sip:{lan_ip}:{lan_port}\r\n"
    "User-Agent: sip-options\r\n"
    "Accept: application/sdp\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)

# Compact header forms (RFC 3261 7.3.3) we need to recognise in replies
COMPACT_HEADERS = {"i": "call-id", "v": "via"}


# Better way to get local ip. 
def get_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.4.4", 53))
        return sock.getsockname()[0]
    finally:
        sock.close()


# Create and reuse one socket.
# connect() on UDP: the kernel drops packets from other sources and reports
# ICMP port-unreachable as ConnectionRefusedError/ConnectionResetError.
# Non-blocking so asyncio can await it directly (no worker threads).
def create_socket(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((ip, port))
    sock.setblocking(False)
    return sock


# ---------- TCP / TLS ----------
# A tcp/tls connection is just the (reader, writer) pair from asyncio.open_connection().
# It is opened on the first request and opened again when the peer closes it or a
# request fails (a timeout may leave it half way through a message).

MAX_BODY = 1 << 20      # largest Content-Length accepted on a stream


# Read one SIP message from a stream. A stream has no message boundaries, so the headers
# are read up to the blank line and the body by its Content-Length (RFC 3261 18.3).
# Any problem is reported as EOFError, with the reason as its message.
async def read_message(reader):
    try:
        while True:
            head = (await reader.readuntil(b"\r\n\r\n")).lstrip(b"\r\n")   # skip CRLF keep-alives
            if head:
                break

        length = 0
        for line in head.decode("utf-8", errors="replace").split("\r\n")[1:]:
            name, _, value = line.partition(":")
            if name.strip().lower() in ("content-length", "l"):
                length = int(value.strip())
                break
        if not 0 <= length <= MAX_BODY:
            raise ValueError(length)

        return head + await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        raise EOFError("connection closed by peer") from None
    except ValueError:
        raise EOFError("invalid Content-Length") from None
    except asyncio.LimitOverrunError:
        raise EOFError("message too large") from None
    except OSError as e:                  # includes ConnectionError and ssl.SSLError
        raise EOFError(str(e)) from e


# One send/receive for any transport: a plain socket for UDP, (reader, writer) for tcp/tls.
# UDP keeps using the plain socket calls.
async def send_data(sock, data):
    if isinstance(sock, tuple):
        try:
            sock[1].write(data)
            await sock[1].drain()
        except OSError as e:
            sock[1].close()
            raise EOFError(str(e)) from e
    else:
        await asyncio.get_running_loop().sock_sendall(sock, data)


async def recv_data(sock):
    if isinstance(sock, tuple):
        try:
            return await read_message(sock[0])
        except BaseException:
            sock[1].close()               # timed out or broken: don't reuse, it may be mid-message
            raise
    return await asyncio.get_running_loop().sock_recv(sock, 4096)


def local_port(sock):
    if isinstance(sock, tuple):
        return sock[1].get_extra_info("sockname")[1]
    return sock.getsockname()[1]


def describe_cert(cert):
    subject = dict(item[0] for item in cert.get("subject", ()))
    name = subject.get("commonName") or next(
        (value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"), "?")
    expires = ssl.cert_time_to_seconds(cert["notAfter"])
    days_left = (expires - time.time()) / 86400
    return (f"server certificate CN={name}, expires "
            f"{time.strftime('%Y-%m-%d', time.gmtime(expires))} ({days_left:.0f} days left)")


# Extra detail printed after connecting: TLS version, cipher and the server certificate
def describe_tls(writer):
    ssl_obj = writer.get_extra_info("ssl_object")
    if ssl_obj is None:
        return ""                         # plain tcp
    text = f" - {ssl_obj.version()}, {ssl_obj.cipher()[0]}"
    if ssl_obj.context.verify_mode == ssl.CERT_NONE:
        return text + "\n  server certificate not verified (-k)"
    return text + "\n  " + describe_cert(ssl_obj.getpeercert())


# Client side TLS settings. By default the server certificate and hostname are verified
# against the system CAs; --cacert replaces them, -k turns verification off.
def make_ssl_context(args):
    ctx = ssl.create_default_context(cafile=args.cacert)
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if args.cert:
        ctx.load_cert_chain(args.cert, args.key)
    return ctx


# Returns a usable (reader, writer), opening a new connection if there is none or the old
# one was closed. Returns None, after printing why, if that fails (the request is then lost).
async def ensure_stream(conn, ip, port, host, ssl_context, timeout, transport):
    if conn is not None:
        reader, writer = conn
        if not (writer.is_closing() or reader.at_eof()):
            return conn
        writer.close()

    label = transport.upper()
    start = time.monotonic()
    try:
        # connect to the already resolved ip, but verify the certificate against the name
        conn = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ssl_context,
                                    server_hostname=host if ssl_context else None),
            timeout=timeout
        )
    except asyncio.TimeoutError:
        print(f"{label} connect timed out")
    except ssl.SSLCertVerificationError as e:
        print(f"TLS certificate verification failed: {e.verify_message}")
    except ssl.SSLError as e:
        print(f"TLS handshake failed: {e}")
    except OSError as e:
        print(f"{label} connect failed: {e}")
    else:
        connect_time = (time.monotonic() - start) * 1000
        print(f"Connected ({label}) in {connect_time:.2f} ms{describe_tls(conn[1])}")
        return conn
    return None


# Close a tcp/tls connection and wait briefly for the peer to finish the shutdown
async def close_stream(conn):
    if conn is None:
        return
    writer = conn[1]
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 1)
    except Exception:
        writer.transport.abort()          # peer never answered the TLS close_notify

# Percentilr calculation
def percentile(data, p):
    if not data:
        return 0
    data = sorted(data)
    k = (len(data) - 1) * (p / 100)
    f = int(k)
    c = min(f + 1, len(data) - 1)
    if f == c:
        return data[f]
    return data[f] + (data[c] - data[f]) * (k - f)


# DNS resolution time calculation
def resolve_target(host):
    #monotonic for better results
    start = time.monotonic()
    try:
        ip = socket.gethostbyname(host)
        dns_time = (time.monotonic() - start) * 1000
        return ip, dns_time
    except socket.gaierror:
        return None, None


# Accepts host or host:port
def split_host_port(dest, default_port):
    if ":" in dest:
        host, port = dest.rsplit(":", 1)
        return host, int(port)
    return dest, default_port


# Parse a SIP response. Returns (status_code, reason, headers) or None if the
# packet is not a SIP response (garbage, a request, wrong protocol, etc.)
def parse_response(data):
    lines = data.decode("utf-8", errors="replace").splitlines()
    if not lines:
        return None

    try:
        proto, code, reason = (lines[0].split(" ", 2) + [""])[:3]
    except ValueError:
        return None
    if proto != "SIP/2.0" or not code.isdigit():
        return None

    headers = {}
    for line in lines[1:]:
        if not line:        # blank line = end of headers
            break
        if ":" in line:
            name, value = line.split(":", 1)
            name = name.strip().lower()
            name = COMPACT_HEADERS.get(name, name)
            headers.setdefault(name, value.strip())   # keep first (top) occurrence

    return int(code), reason, headers


# Does this response belong to the request we just sent?
def matches_request(headers, call_id, cseq, branch):
    if headers.get("call-id") != call_id:
        return False
    if headers.get("cseq", "").split() != [cseq, "OPTIONS"]:
        return False
    via_params = [p.strip() for p in headers.get("via", "").split(";")]
    return f"branch=z9hG4bK{branch}" in via_params


# Verbose output: print a raw SIP message, indented
def dump(label, text):
    print(label)
    for line in text.rstrip().splitlines():
        print(f"    {line}")
    print()


# Send the request, then keep reading until a valid final response for it arrives.
# Stale, foreign, malformed and 1xx packets are ignored. The caller applies the
# timeout with wait_for; cancelling this coroutine leaves nothing running behind.
async def send_and_receive(sock, message, call_id, cseq, branch, verbose=False):
    await send_data(sock, message.encode())
    if verbose:
        dump(">>> Request sent", message)

    while True:
        data = await recv_data(sock)

        parsed = parse_response(data)
        if parsed is None:
            if verbose:
                print(f"<<< Ignored: not a SIP response ({len(data)} bytes)\n")
            continue                      # not a SIP response
        status, reason, headers = parsed
        if not matches_request(headers, call_id, cseq, branch):
            if verbose:
                print(f"<<< Ignored: {status} {reason} does not match this request\n")
            continue                      # late reply to an earlier request / unrelated
        if verbose:
            dump("<<< Response received", data.decode("utf-8", errors="replace"))
        if status < 200:
            continue                      # provisional (100 Trying etc.), wait for final
        return status, reason


async def send_options_request(sock, host, port, timeout, lan_ip, seq, verbose=False, transport="udp"):
    try:
        branch = uuid.uuid4().hex[:16]
        cseq = str(seq)

        lan_port = local_port(sock)

        request = OPTIONS_TEMPLATE.format(
            server=host,   # keep hostname in SIP headers
            port=port,
            via=transport.upper(),
            lan_ip=lan_ip,
            lan_port=lan_port,
            branch=branch,
            call_id=CALL_ID,
            cseq=cseq
        )

        start = time.monotonic()

        try:
            status, reason = await asyncio.wait_for(
                send_and_receive(sock, request, CALL_ID, cseq, branch, verbose),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            print("Request timed out")
            return None
        except EOFError as e:             # tcp/tls: connection lost or unusable data
            print(f"Connection lost: {e}")
            return None
        except ConnectionError:
            print("Port unreachable (ICMP error)")
            return None

        rtt = (time.monotonic() - start) * 1000
        print(f"Reply received: {status} {reason} - {rtt:.2f} ms")
        return rtt

    except Exception as e:
        print(f"Request error: {e}")
        return None


# ---------- Main ----------

async def main():
    parser = argparse.ArgumentParser(
        description="Sends SIP options over UDP, TCP or TLS to an endpoint and shows DNS resolution time, round-trip-time and packet loss percentage ",
        epilog="Exit codes: 0 = all replies received, 1 = packet loss, 2 = error",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("destination", help="SIP server IP/hostname, optionally host:port")
    parser.add_argument("-p", "--port", type=int, default=argparse.SUPPRESS,
                        help="destination port (default: 5060, or 5061 for tls)")
    parser.add_argument("-T", "--transport", choices=["udp", "tcp", "tls"], default="udp")
    parser.add_argument("-c", "--count", type=int, default=5)
    parser.add_argument("-t", "--timeout", type=float, default=3)
    parser.add_argument("-i", "--interval", type=float, default=REQUEST_INTERVAL)
    parser.add_argument("-v", "--verbose", action="store_true", help="print full request and response messages")
    parser.add_argument("-k", "--insecure", action="store_true",
                        help="tls: do not verify the server certificate")
    parser.add_argument("--cacert", metavar="FILE",
                        help="tls: PEM file with the CA(s) to verify the server certificate (replaces the system CAs)")
    parser.add_argument("--cert", metavar="FILE", help="tls: client certificate (PEM) for mutual TLS")
    parser.add_argument("--key", metavar="FILE", help="tls: private key for --cert, if not in the same file")

    args = parser.parse_args()

    if args.transport != "tls" and (args.insecure or args.cacert or args.cert or args.key):
        parser.error("--insecure, --cacert, --cert and --key can only be used with --transport tls")
    if args.key and not args.cert:
        parser.error("--key requires --cert")

    default_port = getattr(args, "port", None) or (SIP_TLS_PORT if args.transport == "tls" else SIP_PORT)
    try:
        host, port = split_host_port(args.destination, default_port)
    except ValueError:
        parser.error(f"invalid destination: {args.destination}")
    if not 0 < port < 65536:
        parser.error(f"invalid port: {port}")

    ssl_context = None
    if args.transport == "tls":
        try:
            ssl_context = make_ssl_context(args)
        except (OSError, ssl.SSLError) as e:
            print(f"TLS setup error: {e}")
            return EXIT_ERROR

    num_requests = args.count
    timeout = args.timeout

    try:
        lan_ip = get_local_ip()
    except OSError as e:
        print(f"Could not determine local IP: {e}")
        return EXIT_ERROR

    # DNS resolution
    ip, dns_time = resolve_target(host)

    if ip is None:
        print("DNS resolution failed")
        return EXIT_ERROR

    try:
        sock = create_socket(ip, port) if args.transport == "udp" else None   # tcp/tls connect on the first request
    except OSError as e:
        print(f"Socket error: {e}")
        return EXIT_ERROR

    print(f"\nSending SIP Option to: {host} ({ip}), port {port}/{args.transport.upper()}")
    print(f"DNS resolution time: {dns_time:.2f} ms")
    #print(f"Local IP: {lan_ip}")
    print(f"Requests: {num_requests}, Timeout: {timeout}s\n")

    sent = 0
    received = 0
    rtt_list = []

    try:
        for seq in range(1, num_requests + 1):
            start = time.monotonic()
            if args.transport != "udp":
                sock = await ensure_stream(sock, ip, port, host, ssl_context, timeout, args.transport)
            rtt = None
            if sock is not None:
                rtt = await send_options_request(sock, host, port, timeout, lan_ip, seq, args.verbose, args.transport)

            sent += 1
            if rtt is not None:
                received += 1
                rtt_list.append(rtt)

            # sleep only for what is left of the interval so the cadence doesn't drift
            await asyncio.sleep(max(0, args.interval - (time.monotonic() - start)))

    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\nInterrupted")      # fall through to the summary, like ping
    finally:
        if args.transport == "udp":
            sock.close()
        else:
            await close_stream(sock)

    # ---------- Summary ----------

    print("\n----- Summary -----")

    loss = ((sent - received) / sent) * 100 if sent else 0
    print(f"{sent} sent, {received} received, {loss:.2f}% packet loss")

    print(f"DNS resolution: {dns_time:.2f} ms")

    if rtt_list:
        avg = sum(rtt_list) / len(rtt_list)

        print(f"rtt min/avg/max: {min(rtt_list):.2f}/{avg:.2f}/{max(rtt_list):.2f} ms")

        if len(rtt_list) >= 2:
            stddev = statistics.stdev(rtt_list)
            # jitter = mean absolute difference between consecutive RTTs
            jitter = sum(abs(b - a) for a, b in zip(rtt_list, rtt_list[1:])) / (len(rtt_list) - 1)
            print(f"stddev: {stddev:.2f} ms, jitter: {jitter:.2f} ms")

        if len(rtt_list) >= PERCENTILE_MIN_SAMPLES:
            print(
                f"percentiles p50/p95/p99: "
                f"{percentile(rtt_list,50):.2f}/"
                f"{percentile(rtt_list,95):.2f}/"
                f"{percentile(rtt_list,99):.2f} ms"
            )
    else:
        print("No successful responses")

    return EXIT_OK if sent and received == sent else EXIT_LOSS


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(EXIT_LOSS)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(EXIT_ERROR)
        
 
#
# ToDo
# - Add customization for Options Template
# - have commandline arguments for template to use
# ########################
# - references
# https://docs.python.org/3/library/socket.html#functions
# https://docs.python.org/3/library/asyncio.html
# https://docs.python.org/3/library/uuid.html
# https://docs.python.org/3/library/time.html#time.monotonic
# https://docs.python.org/3/library/argparse.html#module-argparse
# https://docs.python.org/3.12/library/statistics.html
# https://docs.python.org/3/library/ssl.html
#
# 
