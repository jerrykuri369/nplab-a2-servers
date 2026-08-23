# NPLAB Assignment 2 — tcpServer and udpServer

TCP and UDP calculation servers for the BTH network programming lab.
Same TEXT / BINARY 1.1 API as Assignment 1.

```
./tcpserver host:port
./udpserver host:port
```

`host` may be a DNS name, IPv4 address, or IPv6 address (`[::1]:5000`).
Special names `ip4-localhost` and `ip6-localhost` bind loopback of that family.

## Build (Ubuntu 24.04 / 25.10 and macOS)

```bash
sudo apt install -y build-essential   # Ubuntu
make
```

Produces `tcpserver` and `udpserver`. No OpenSSL.

## TCP (`fork`)

- One child process per connection.
- Advertises `TEXT TCP 1.1` and `BINARY TCP 1.1`.
- Client replies `TEXT TCP 1.1 OK` or `BINARY TCP 1.1 OK`.
- Job: `add|sub|mul|div A B` (text) or a packed `calcProtocol` (binary).
- Correct answer → `OK\n` (text) or `calcMessage` with `message=1` (binary).
- Each step has a **5 second** limit. On timeout the child sends `ERROR TO\n` and exits.

## UDP (`select`)

- One socket, many clients. Client identity is the source address.
- First datagram: `TEXT UDP 1.1\n` or binary `calcMessage` type 22.
- Server stores the client and sends a job.
- Second datagram: the answer. Compared to the stored result.
- **10 seconds** to answer. After that the client is dropped; a reply at 11 s is rejected.
- Division never uses a zero divisor.

## Protocol sizes (packed)

| Message        | Bytes |
|----------------|-------|
| `calcMessage`  | 12    |
| `calcProtocol` | 26    |
| `TEXT UDP 1.1\n` | 13  |
