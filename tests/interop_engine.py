import os
import sys
import threading
import time

from yuumi import (
    Channel,
    Engine,
    EngineConfig,
    EngineError,
    ErrorKind,
    FragmentationSettings,
    HeartbeatSettings,
    StatusCode,
)


endpoint = os.environ.get("YUUMI_ENDPOINT_NAME")
token = os.environ.get("YUUMI_TOKEN")
scenario = os.environ.get("YUUMI_INTEROP_SCENARIO")
engine_name = os.environ.get("YUUMI_INTEROP_ENGINE_NAME")
if not endpoint or not token or not scenario or not engine_name:
    raise RuntimeError("interop fixture environment is incomplete")

config = EngineConfig(
    endpoint,
    token,
    connect_timeout=5.0,
    application_queue_capacity=1 if scenario == "backpressure" else 64,
    heartbeat=(
        HeartbeatSettings(False, 0.05, 20)
        if scenario == "slow"
        else HeartbeatSettings(True)
    ),
    fragmentation=FragmentationSettings(0.15, 16),
)
engine = Engine(config)
finished = threading.Event()
close_requested = threading.Event()
captured_responder = None
connection_count = 0
terminal_kind = None
failure = None


def report(name, **values):
    return {"event": name, "engine": engine_name, **values}


def error_kind(error):
    return error.kind.value if isinstance(error, EngineError) else "unknown"


def on_connected(_session):
    global connection_count, failure
    connection_count += 1
    if scenario != "reconnect" or connection_count != 2:
        return
    try:
        captured_responder.respond({"unexpected": True})
        responder = "not_rejected"
    except Exception as error:
        responder = error_kind(error)
    try:
        engine.send(Channel.COMMAND, {"unexpected": True})
        send = "not_rejected"
    except Exception as error:
        send = error_kind(error)
    try:
        engine.send(Channel.DATA, report("stale", responder=responder, send=send))
    except Exception as error:
        failure = error
        finished.set()


def on_message(message):
    global captured_responder
    if isinstance(message.payload, str):
        engine.send(Channel.DATA, report("limit", size=len(message.payload)))
        return
    operation = message.payload.get("op") if isinstance(message.payload, dict) else None
    if operation == "roundtrip":
        message.responder.respond(report("response", opaque=message.payload["opaque"]))
        engine.send(Channel.LOG, report("uncorrelated"))
    elif operation == "fragmented":
        engine.send(
            Channel.DATA,
            report("fragmented", size=len(str(message.payload.get("payload", "")))),
        )
    elif operation == "slow":
        time.sleep(0.3)
        message.responder.respond(report("slow_complete"))
    elif operation == "hold":
        time.sleep(0.5)
    elif operation == "capture":
        captured_responder = message.responder
        engine.send(Channel.DATA, report("captured"))
    elif operation == "reuse":
        message.responder.respond(report("reuse_response"))
        try:
            message.responder.respond({"unexpected": True})
            kind = "not_rejected"
        except Exception as error:
            kind = error_kind(error)
        engine.send(Channel.DATA, report("responder_reuse", kind=kind))
    elif operation == "engine_close":
        message.responder.respond(report("closing"))
        close_requested.set()


def on_error(error):
    global terminal_kind
    terminal_kind = error.kind
    if error.status == StatusCode.ERR_FRAGMENT_TIMEOUT:
        engine.send(
            Channel.DATA,
            report("fragment_timeout", code=int(error.status)),
        )


def reconnect():
    global failure
    try:
        time.sleep(0.02)
        engine.connect()
    except Exception as error:
        failure = error
        finished.set()


def on_disconnected(_event):
    global failure
    if scenario == "reconnect" and connection_count == 1:
        threading.Thread(
            target=reconnect,
            name="yuumi-interop-python-reconnect",
            daemon=False,
        ).start()
        return
    if scenario == "oversize" and terminal_kind != ErrorKind.PROTOCOL:
        failure = RuntimeError(f"oversize terminal kind was {terminal_kind}")
    elif scenario == "backpressure" and terminal_kind != ErrorKind.BACKPRESSURE:
        failure = RuntimeError(f"backpressure terminal kind was {terminal_kind}")
    finished.set()


engine.on_session_connected(on_connected)
engine.on_message(on_message)
engine.on_error(on_error)
engine.on_session_disconnected(on_disconnected)

try:
    engine.connect()
    while not finished.wait(0.01):
        if close_requested.is_set():
            engine.close()
    engine.close()
    if failure is not None:
        raise failure
except Exception as error:
    print(str(error), file=sys.stderr)
    sys.exit(1)


"""
This private executable applies only test-application scenario policy. The
Python SDK remains a single-attempt engine dialer with explicit worker cleanup.
"""
