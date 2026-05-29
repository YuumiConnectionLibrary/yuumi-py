# yuumi-py

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)

> Python SDK for the [Yuumi IPC protocol](https://github.com/YuumiConnectionLibrary/yuumi-spec) — connect your Python backend to a Go frontend over a local Unix socket.

## Install

```bash
pip install yuumi-py
```

Only one external dependency: [`msgpack`](https://pypi.org/project/msgpack/).

## Quick start

```python
from yuumi import connect, Channel

with connect("my-service") as client:
    client.on_message(lambda data, ch: print(f"channel={ch.name} data={data}"))
    client.on_heartbeat(lambda ts: print(f"heartbeat ts={ts}"))
    client.on_error(lambda err: print(f"error: {err}"))
    client.listen()

    client.send({"status": "ready"}, Channel.COMMAND)

    data, channel = client.receive()
    print(data, channel)
```

## Reconnect policy

```python
from yuumi import connect, ReconnectPolicy

client = connect("my-service", policy=ReconnectPolicy(
    max_attempts=5,
    initial_delay=0.1,   # seconds
    max_delay=2.0,
))
```

## API reference

| Symbol | Description |
|---|---|
| `connect(pipe_name, policy?, timeout?)` | Dial, handshake, return `Client` |
| `Client.connect(pipe_name, timeout?)` | Class-method equivalent |
| `Client.connect_with_policy(pipe_name, policy, timeout?)` | Dial with exponential-backoff retry |
| `client.send(data, channel)` | Encode and send a data frame |
| `client.receive()` | Read one frame synchronously → `(data, channel)` |
| `client.listen()` | Start daemon read thread |
| `client.on_message(fn)` | `fn(data: dict, channel: Channel)` |
| `client.on_heartbeat(fn)` | `fn(ts: int)` — called only for heartbeat frames on ChannelControl |
| `client.on_error(fn)` | `fn(err: YuumiError)` — called on transport / protocol errors |
| `client.close()` | Shut down connection |
| `Client` as context manager | `with connect(...) as c:` — calls `close()` automatically |
| `ReconnectPolicy` | Dataclass: `max_attempts`, `initial_delay`, `max_delay`, `jitter` |
| `Diagnostic` | Structured stdout logging: `.log()`, `.error()`, `.success()` |

## Channels

| Constant | Value | Purpose |
|---|---|---|
| `Channel.CONTROL` | `0` | Heartbeat, lifecycle |
| `Channel.COMMAND` | `1` | Commands |
| `Channel.LOG` | `2` | Log output |
| `Channel.DATA` | `3` | Application payload |

## Requirements

- Python 3.11+
- Linux, macOS, Windows 10 1803+

## Wire protocol

See [yuumi-spec](https://github.com/YuumiConnectionLibrary/yuumi-spec) for the canonical wire format and conformance test vectors.

## Issues

Questions or problems? [Open an issue](https://github.com/YuumiConnectionLibrary/yuumi-py/issues).
