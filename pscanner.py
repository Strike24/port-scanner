#!/usr/bin/env python3
# simple_async_scan_fixed.py
import asyncio
import argparse

# Uses asyncio and does a full tcp handshake to detrmine if the port is open.
async def is_port_open(host, port, timeout=1.0):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        print(f"{host}:{port} ✅")
        return port, True
    except Exception:
        return port, False

# Uses asyncio "semaphore" to run multiple councurrent port checks at the same time
async def scan_ports(host, ports, concurrency=500, timeout=1.0):
    semaphore = asyncio.Semaphore(concurrency)

    async def sem_check(p):
        async with semaphore:
            return await is_port_open(host, p, timeout)

    tasks = [asyncio.create_task(sem_check(p)) for p in ports]
    results = await asyncio.gather(*tasks)
    open_ports = [p for p, ok in results if ok]
    return sorted(open_ports)

# Banner grabbing function to get service info for open port
async def service_info(host, port, timeout=1.0):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)

        # Some ports require sending a request to send back data.
        # For HTTP/HTTPS, we can send a simple GET request.
        request = f"GET / HTTP/1.0\r\nConnection: close\r\n\r\n"
        writer.write(request.encode('utf-8'))
        await writer.drain()

        if port == 21:
            # For FTP, send a simple command to elicit a response
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
        elif port == 445 or port == 139:
            # For SMB,  assume a banner
            banner = "SMB2"


        data = await asyncio.wait_for(reader.read(1024), timeout)
        banner = data.decode('utf-8', errors="ignore").strip()

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        return port, banner if banner else None
    except Exception:
        return port, None

# Initialize arguments
def init_args():
    parser = argparse.ArgumentParser(description="Simple async port scanner")
    parser.add_argument("host", nargs="?", default="127.0.0.1", help="Target host (IP or hostname)")
    # use descriptive option names and sensible dests
    parser.add_argument("-s", "--start", dest="start_port", type=int, default=1,
                        help="Starting port (inclusive)")
    parser.add_argument("-e", "--end", dest="end_port", type=int, default=1024,
                        help="Ending port (inclusive)")
    parser.add_argument("-c", "--concurrency", type=int, default=500,
                        help="Maximum concurrent connection attempts")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds")
    return parser.parse_args()

if __name__ == "__main__":
    args = init_args()
    host = args.host
    # validate and build the port range (inclusive)
    start = max(1, args.start_port)
    end = min(65535, args.end_port)
    if start > end:
        raise SystemExit("Invalid port range: start must be <= end.")
    ports = range(start, end + 1)

    open_ports = asyncio.run(scan_ports(host, ports, concurrency=args.concurrency, timeout=args.timeout))
    print("⏱️ Fetching service banners...")
    banners = [asyncio.run(service_info(host, p, timeout=args.timeout)) for p in open_ports]
    print("-----------")
    if open_ports:
        for p, banner in banners:
            if banner:
                print(f"{host}:{p} - OPEN - {banner.splitlines()[0] if banner else banner}")
            else:
                print(f"{host}:{p} - OPEN")
        print(f"Found {len(open_ports)} open ports on {host}.")
    else:
        print(f"No open ports found on {host} in the range {start}-{end}.")
