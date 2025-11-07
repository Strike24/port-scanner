# Simple Async Port Scanner with Asyncio
# Todos:
# 1. Upgrade TCP Handshake to only do a SYN scan. (Stealthier)
# 2. Grab banner info about an open port found (get information about the service itself)
# 3, Clean code, seperate into seprate files

import socket
import sys
import asyncio

async def is_port_open(host, port, timeout=1.0):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        print(f"{host}:{port} - OPEN\n")        
        return port, True
    except Exception:
        return port, False

async def scan_ports(host, ports, amount=500, timeout=1.0):
    semaphore = asyncio.Semaphore(amount) # Run port checking concurrently using semaphore
    async def sem_check(p): # Task - check if port is open
        async with semaphore:
            return await is_port_open(host, p, timeout)
        
    tasks = [asyncio.create_task(sem_check(p)) for p in ports] # Creates task for each port
    results = await asyncio.gather(*tasks)
    open_ports = [p for p, ok in results if ok]
    return sorted(open_ports) #return a list of all open ports sorted

if __name__ == "__main__":
    host = "raspberrypi.local"
    ports = range(1, 8000)
    open_ports = asyncio.run(scan_ports(host, ports))
    print(f"-----------\nFound {len(open_ports)} Ports open on host.")