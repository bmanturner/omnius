#!/usr/bin/env python3

import argparse
import concurrent.futures
import copy
import datetime as dt
import http.client
import json
import math
import os
import platform
import queue
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any, Optional

SCHEMA_VERSION = 1
SERVER_SCENARIOS = {"http_load", "http_soak", "graceful_rollout"}
SCENARIO_ORDER = [
    "http_load",
    "http_soak",
    "auth_burst",
    "pool_saturation",
    "cache_outage",
    "redis_reconnect",
    "queue_backlog",
    "realtime_slow_consumers",
    "graceful_rollout",
    "dependency_latency",
]
CONTRACT_SCENARIOS = set(SCENARIO_ORDER) - SERVER_SCENARIOS
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
STARTED_ADDRESS = re.compile(r"startup complete listen_address=(127\.0\.0\.1:\d+)")
REQUEST_PATHS = ("/live", "/example")


class ConfigurationError(ValueError):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def write_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def violation(metric: str, observed: Any, operator: str, threshold: Any) -> dict[str, Any]:
    return {
        "metric": metric,
        "observed": observed,
        "operator": operator,
        "threshold": threshold,
    }


def percentile(values: list[float], percent: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil((percent / 100.0) * len(ordered)) - 1)
    return ordered[index]


def expected_response(path: str, status: int, body: bytes) -> bool:
    if status != 200:
        return False
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if path == "/live":
        return payload == {"status": "live"}
    return payload == {"message": "hello from minimal-reference"}


def request_once(
    address: tuple[str, int], path: str, timeout: float, sequence: int
) -> dict[str, Any]:
    started = time.perf_counter()
    connection = http.client.HTTPConnection(address[0], address[1], timeout=timeout)
    status: Optional[int] = None
    failure: Optional[str] = None
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        status = response.status
        body = response.read(4096)
        if not expected_response(path, status, body):
            failure = "unexpected_response"
    except (OSError, http.client.HTTPException, TimeoutError):
        failure = "transport_error"
    finally:
        connection.close()
    return {
        "sequence": sequence,
        "path": path,
        "status": status,
        "ok": failure is None,
        "failure": failure,
        "latency_ms": round((time.perf_counter() - started) * 1000.0, 3),
    }


def complete_draining_request(
    connection: socket.socket, sequence: int, shutdown_started: float
) -> dict[str, Any]:
    path = "/example"
    status: Optional[int] = None
    failure: Optional[str] = None
    response: Optional[http.client.HTTPResponse] = None
    try:
        connection.sendall(b"\r\n\r\n")
        response = http.client.HTTPResponse(connection)
        response.begin()
        status = response.status
        body = response.read(4096)
        if not expected_response(path, status, body):
            failure = "unexpected_response"
    except (OSError, http.client.HTTPException, TimeoutError):
        failure = "transport_error"
    finally:
        if response is not None:
            response.close()
        connection.close()
    return {
        "sequence": sequence,
        "source_process": "draining",
        "path": path,
        "status": status,
        "ok": failure is None,
        "failure": failure,
        "latency_ms": round((time.perf_counter() - shutdown_started) * 1000.0, 3),
    }


def fixed_requests(
    address: tuple[str, int], total: int, concurrency: int, timeout: float
) -> tuple[list[dict[str, Any]], float]:
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(
                request_once,
                address,
                REQUEST_PATHS[index % len(REQUEST_PATHS)],
                timeout,
                index,
            )
            for index in range(total)
        ]
        samples = [future.result() for future in futures]
    return samples, time.perf_counter() - started


def paced_requests(
    address: tuple[str, int],
    duration_seconds: float,
    requests_per_second: int,
    concurrency: int,
    timeout: float,
) -> tuple[list[dict[str, Any]], float]:
    total = max(1, int(round(duration_seconds * requests_per_second)))
    started = time.perf_counter()
    deadline = started + duration_seconds

    def worker(offset: int) -> list[dict[str, Any]]:
        samples = []
        for index in range(offset, total, concurrency):
            path = REQUEST_PATHS[index % len(REQUEST_PATHS)]
            scheduled = started + (index / requests_per_second)
            delay = scheduled - time.perf_counter()
            if delay > 0:
                time.sleep(delay)
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                samples.append(
                    {
                        "sequence": index,
                        "path": path,
                        "status": None,
                        "ok": False,
                        "failure": "soak_deadline_exhausted",
                        "latency_ms": 0.0,
                    }
                )
                continue
            samples.append(request_once(address, path, min(timeout, remaining), index))
        return samples

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        batches = list(executor.map(worker, range(concurrency)))
    samples = [sample for batch in batches for sample in batch]
    samples.sort(key=lambda sample: sample["sequence"])
    return samples, time.perf_counter() - started


def request_metrics(samples: list[dict[str, Any]], duration_seconds: float) -> dict[str, Any]:
    latencies = [float(sample["latency_ms"]) for sample in samples]
    failures = Counter(sample["failure"] for sample in samples if sample["failure"] is not None)
    statuses = Counter(str(sample["status"]) for sample in samples if sample["status"] is not None)
    succeeded = sum(1 for sample in samples if sample["ok"])
    total = len(samples)
    return {
        "requests": total,
        "succeeded": succeeded,
        "failed": total - succeeded,
        "error_rate": round((total - succeeded) / total, 6) if total else 1.0,
        "duration_seconds": round(duration_seconds, 6),
        "requests_per_second": round(total / duration_seconds, 3) if duration_seconds else 0.0,
        "latency_ms": {
            "min": round(min(latencies), 3) if latencies else 0.0,
            "p50": round(percentile(latencies, 50), 3),
            "p95": round(percentile(latencies, 95), 3),
            "p99": round(percentile(latencies, 99), 3),
            "max": round(max(latencies), 3) if latencies else 0.0,
        },
        "status_counts": dict(sorted(statuses.items())),
        "failure_counts": dict(sorted(failures.items())),
    }


def rss_bytes(pid: int) -> Optional[int]:
    status = Path(f"/proc/{pid}/status")
    if status.is_file():
        for line in status.read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                fields = line.split()
                return int(fields[1]) * 1024
        return None
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["ps", "-o", "rss=", "-p", str(pid)],
                check=True,
                capture_output=True,
                text=True,
                timeout=2,
            )
            return int(result.stdout.strip()) * 1024
        except (OSError, subprocess.SubprocessError, ValueError):
            return None
    return None


def memory_bytes() -> Optional[int]:
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
        return None
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["sysctl", "-n", "hw.memsize"],
                check=True,
                capture_output=True,
                text=True,
                timeout=2,
            )
            return int(result.stdout.strip())
        except (OSError, subprocess.SubprocessError, ValueError):
            return None
    return None


def cpu_model() -> Optional[str]:
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(encoding="utf-8").splitlines():
            if line.startswith(("model name", "Hardware")):
                return line.partition(":")[2].strip() or None
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                check=True,
                capture_output=True,
                text=True,
                timeout=2,
            )
            return result.stdout.strip() or None
        except (OSError, subprocess.SubprocessError):
            return None
    return platform.processor() or None


def machine_metadata() -> dict[str, Any]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "cpu_model": cpu_model(),
        "cpu_count": os.cpu_count(),
        "memory_bytes": memory_bytes(),
        "python": platform.python_version(),
    }


def stop_process(process: subprocess.Popen[Any], grace_seconds: float = 3.0) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        process.terminate()
    try:
        process.wait(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        process.kill()
    process.wait(timeout=grace_seconds)


def command_step(
    command: list[str], timeout_seconds: float, output_dir: Path, stem: str, workspace: Path
) -> dict[str, Any]:
    stdout_path = output_dir / f"{stem}.stdout.log"
    stderr_path = output_dir / f"{stem}.stderr.log"
    started = time.perf_counter()
    timed_out = False
    launch_error: Optional[str] = None
    exit_code: Optional[int] = None
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(workspace / "target")
    environment["CARGO_TERM_COLOR"] = "never"
    environment["SQLX_OFFLINE"] = "true"
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        try:
            process = subprocess.Popen(
                command,
                cwd=workspace,
                env=environment,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
        except OSError as error:
            launch_error = error.__class__.__name__
        else:
            try:
                exit_code = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                stop_process(process)
                exit_code = process.returncode
            except BaseException:
                stop_process(process)
                raise
    return {
        "command": command,
        "duration_seconds": round(time.perf_counter() - started, 6),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "launch_error": launch_error,
        "stdout_artifact": stdout_path.name,
        "stderr_artifact": stderr_path.name,
    }


class ServiceProcess:
    def __init__(
        self,
        binary: Path,
        workspace: Path,
        output_dir: Path,
        name: str,
        startup_timeout_seconds: float,
    ) -> None:
        self.binary = binary
        self.workspace = workspace
        self.output_dir = output_dir
        self.name = name
        self.startup_timeout_seconds = startup_timeout_seconds
        self.process: Optional[subprocess.Popen[str]] = None
        self.address: Optional[tuple[str, int]] = None
        self._stdout = None
        self._stderr_log = None
        self._reader: Optional[threading.Thread] = None
        self._addresses: queue.Queue[str] = queue.Queue()

    @property
    def pid(self) -> int:
        if self.process is None:
            raise RuntimeError("service has not started")
        return self.process.pid

    def start(self) -> tuple[str, int]:
        self._stdout = (self.output_dir / f"{self.name}.stdout.log").open("w", encoding="utf-8")
        self._stderr_log = (self.output_dir / f"{self.name}.stderr.log").open(
            "w", encoding="utf-8"
        )
        command = [
            str(self.binary),
            "server",
            "--config",
            str(self.workspace / "config/minimal.toml"),
            "--listen-address",
            "127.0.0.1:0",
        ]
        environment = {
            key: value for key, value in os.environ.items() if not key.startswith("OMNIUS__")
        }
        self.process = subprocess.Popen(
            command,
            cwd=self.workspace,
            env=environment,
            stdout=self._stdout,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._reader = threading.Thread(target=self._read_stderr, daemon=True)
        self._reader.start()
        deadline = time.monotonic() + self.startup_timeout_seconds
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self._finalize_logs()
                raise RuntimeError(f"service exited during startup with code {self.process.returncode}")
            try:
                address = self._addresses.get(timeout=0.05)
            except queue.Empty:
                continue
            host, port = address.rsplit(":", 1)
            self.address = (host, int(port))
            return self.address
        self.kill()
        raise RuntimeError("service startup exceeded its deadline")

    def _read_stderr(self) -> None:
        if self.process is None or self.process.stderr is None or self._stderr_log is None:
            return
        for line in self.process.stderr:
            self._stderr_log.write(line)
            self._stderr_log.flush()
            match = STARTED_ADDRESS.search(line)
            if match is not None:
                self._addresses.put(match.group(1))
        self.process.stderr.close()

    def begin_shutdown(self) -> float:
        if self.process is None:
            raise RuntimeError("service has not started")
        started = time.perf_counter()
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
        return started

    def remains_running_for(self, duration_seconds: float) -> bool:
        if self.process is None:
            raise RuntimeError("service has not started")
        try:
            self.process.wait(timeout=duration_seconds)
        except subprocess.TimeoutExpired:
            return True
        return False

    def wait_for_shutdown(self, started: float, timeout_seconds: float) -> dict[str, Any]:
        if self.process is None:
            raise RuntimeError("service has not started")
        remaining = max(0.0, timeout_seconds - (time.perf_counter() - started))
        forced = False
        try:
            exit_code = self.process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            forced = True
            self.process.kill()
            exit_code = self.process.wait(timeout=3)
        duration = time.perf_counter() - started
        self._finalize_logs()
        return {
            "duration_seconds": round(duration, 6),
            "exit_code": exit_code,
            "forced": forced,
        }

    def signal_and_wait(self, timeout_seconds: float) -> dict[str, Any]:
        return self.wait_for_shutdown(self.begin_shutdown(), timeout_seconds)

    def kill(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=3)
        self._finalize_logs()

    def _finalize_logs(self) -> None:
        if self._reader is not None:
            self._reader.join(timeout=2)
            self._reader = None
        if self._stdout is not None:
            self._stdout.close()
            self._stdout = None
        if self._stderr_log is not None:
            self._stderr_log.close()
            self._stderr_log = None


def load_thresholds(metrics: dict[str, Any], thresholds: dict[str, Any]) -> list[dict[str, Any]]:
    violations = []
    if metrics["error_rate"] > thresholds["max_error_rate"]:
        violations.append(
            violation("error_rate", metrics["error_rate"], "<=", thresholds["max_error_rate"])
        )
    if metrics["latency_ms"]["p95"] > thresholds["max_p95_latency_ms"]:
        violations.append(
            violation(
                "latency_ms.p95",
                metrics["latency_ms"]["p95"],
                "<=",
                thresholds["max_p95_latency_ms"],
            )
        )
    if metrics["requests_per_second"] < thresholds.get("min_requests_per_second", 0):
        violations.append(
            violation(
                "requests_per_second",
                metrics["requests_per_second"],
                ">=",
                thresholds["min_requests_per_second"],
            )
        )
    return violations


def run_http_load(
    binary: Path, workspace: Path, output_dir: Path, config: dict[str, Any]
) -> dict[str, Any]:
    started_at = utc_now()
    started = time.perf_counter()
    service = ServiceProcess(
        binary,
        workspace,
        output_dir,
        "http-load-server",
        float(config["startup_timeout_seconds"]),
    )
    violations = []
    samples: list[dict[str, Any]] = []
    metrics: dict[str, Any] = {}
    shutdown: dict[str, Any] = {}
    try:
        address = service.start()
        warmup, _ = fixed_requests(
            address,
            int(config["warmup_requests"]),
            min(int(config["concurrency"]), int(config["warmup_requests"])),
            float(config["request_timeout_seconds"]),
        )
        warmup_failures = sum(1 for sample in warmup if not sample["ok"])
        if warmup_failures:
            violations.append(violation("warmup_failures", warmup_failures, "==", 0))
        samples, duration = fixed_requests(
            address,
            int(config["requests"]),
            int(config["concurrency"]),
            float(config["request_timeout_seconds"]),
        )
        metrics = request_metrics(samples, duration)
        violations.extend(load_thresholds(metrics, config["thresholds"]))
        shutdown = service.signal_and_wait(
            float(config["thresholds"]["max_shutdown_seconds"])
        )
        if shutdown["forced"] or shutdown["exit_code"] != 0:
            violations.append(violation("graceful_exit_code", shutdown["exit_code"], "==", 0))
    except Exception as error:
        violations.append(violation("scenario_exception", error.__class__.__name__, "==", None))
    finally:
        service.kill()
    return {
        "id": "http_load",
        "status": "passed" if not violations else "failed",
        "started_at": started_at,
        "completed_at": utc_now(),
        "duration_seconds": round(time.perf_counter() - started, 6),
        "thresholds": config["thresholds"],
        "metrics": metrics,
        "shutdown": shutdown,
        "violations": violations,
        "samples": samples,
    }


def run_http_soak(
    binary: Path, workspace: Path, output_dir: Path, config: dict[str, Any]
) -> dict[str, Any]:
    started_at = utc_now()
    started = time.perf_counter()
    service = ServiceProcess(
        binary,
        workspace,
        output_dir,
        "http-soak-server",
        float(config["startup_timeout_seconds"]),
    )
    violations = []
    samples: list[dict[str, Any]] = []
    metrics: dict[str, Any] = {}
    memory: dict[str, Any] = {}
    shutdown: dict[str, Any] = {}
    try:
        address = service.start()
        warmup, _ = fixed_requests(
            address,
            int(config["concurrency"]),
            int(config["concurrency"]),
            float(config["request_timeout_seconds"]),
        )
        warmup_failures = sum(1 for sample in warmup if not sample["ok"])
        if warmup_failures:
            violations.append(violation("warmup_failures", warmup_failures, "==", 0))
        rss_before = rss_bytes(service.pid)
        rss_samples = [rss_before] if rss_before is not None else []
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            soak = executor.submit(
                paced_requests,
                address,
                float(config["duration_seconds"]),
                int(config["requests_per_second"]),
                int(config["concurrency"]),
                float(config["request_timeout_seconds"]),
            )
            while not soak.done():
                current_rss = rss_bytes(service.pid)
                if current_rss is not None:
                    rss_samples.append(current_rss)
                time.sleep(0.25)
            samples, duration = soak.result()
        rss_after = rss_bytes(service.pid)
        if rss_after is not None:
            rss_samples.append(rss_after)
        rss_peak = max(rss_samples) if rss_samples else None
        growth = (
            None if rss_before is None or rss_peak is None else max(0, rss_peak - rss_before)
        )
        memory = {
            "rss_before_bytes": rss_before,
            "rss_after_bytes": rss_after,
            "rss_peak_bytes": rss_peak,
            "rss_peak_growth_bytes": growth,
        }
        metrics = request_metrics(samples, duration)
        thresholds = config["thresholds"]
        if metrics["error_rate"] > thresholds["max_error_rate"]:
            violations.append(
                violation("error_rate", metrics["error_rate"], "<=", thresholds["max_error_rate"])
            )
        if metrics["latency_ms"]["p99"] > thresholds["max_p99_latency_ms"]:
            violations.append(
                violation(
                    "latency_ms.p99",
                    metrics["latency_ms"]["p99"],
                    "<=",
                    thresholds["max_p99_latency_ms"],
                )
            )
        if metrics["requests_per_second"] < thresholds["min_requests_per_second"]:
            violations.append(
                violation(
                    "requests_per_second",
                    metrics["requests_per_second"],
                    ">=",
                    thresholds["min_requests_per_second"],
                )
            )
        if growth is None:
            violations.append(
                violation(
                    "rss_peak_growth_bytes", None, "<=", thresholds["max_rss_growth_bytes"]
                )
            )
        elif growth > thresholds["max_rss_growth_bytes"]:
            violations.append(
                violation(
                    "rss_peak_growth_bytes", growth, "<=", thresholds["max_rss_growth_bytes"]
                )
            )
        shutdown = service.signal_and_wait(
            float(config["thresholds"]["max_shutdown_seconds"])
        )
        if shutdown["forced"] or shutdown["exit_code"] != 0:
            violations.append(violation("graceful_exit_code", shutdown["exit_code"], "==", 0))
    except Exception as error:
        violations.append(violation("scenario_exception", error.__class__.__name__, "==", None))
    finally:
        service.kill()
    return {
        "id": "http_soak",
        "status": "passed" if not violations else "failed",
        "started_at": started_at,
        "completed_at": utc_now(),
        "duration_seconds": round(time.perf_counter() - started, 6),
        "configured_duration_seconds": config["duration_seconds"],
        "thresholds": config["thresholds"],
        "metrics": metrics,
        "memory": memory,
        "shutdown": shutdown,
        "violations": violations,
        "samples": samples,
    }


def run_graceful_rollout(
    binary: Path, workspace: Path, output_dir: Path, config: dict[str, Any]
) -> dict[str, Any]:
    started_at = utc_now()
    started = time.perf_counter()
    startup_timeout = float(config["startup_timeout_seconds"])
    old = ServiceProcess(binary, workspace, output_dir, "rollout-old-server", startup_timeout)
    replacement = ServiceProcess(
        binary, workspace, output_dir, "rollout-replacement-server", startup_timeout
    )
    violations = []
    samples: list[dict[str, Any]] = []
    metrics: dict[str, Any] = {}
    old_shutdown: dict[str, Any] = {}
    replacement_shutdown: dict[str, Any] = {}
    drain_sockets: list[socket.socket] = []
    try:
        old_address = old.start()
        replacement_address = replacement.start()
        old_warmup, _ = fixed_requests(
            old_address, 8, 4, float(config["request_timeout_seconds"])
        )
        replacement_warmup, _ = fixed_requests(
            replacement_address, 8, 4, float(config["request_timeout_seconds"])
        )
        warmup_failures = sum(
            1 for sample in old_warmup + replacement_warmup if not sample["ok"]
        )
        if warmup_failures:
            violations.append(violation("warmup_failures", warmup_failures, "==", 0))
        request_timeout = float(config["request_timeout_seconds"])
        drain_count = min(int(config["concurrency"]), int(config["requests"]) // 2)
        incomplete = (
            f"GET /example HTTP/1.1\r\nHost: {old_address[0]}:{old_address[1]}"
            "\r\nConnection: close\r\nX-Incomplete:"
        ).encode("ascii")
        for _ in range(drain_count):
            connection = socket.create_connection(old_address, timeout=request_timeout)
            connection.settimeout(request_timeout)
            connection.sendall(incomplete)
            drain_sockets.append(connection)

        traffic_started = time.perf_counter()
        shutdown_started = old.begin_shutdown()
        observation_threshold = float(
            config["thresholds"]["min_drain_observation_seconds"]
        )
        held_inflight = old.remains_running_for(observation_threshold)
        observation_seconds = time.perf_counter() - shutdown_started
        if not held_inflight:
            violations.append(
                violation(
                    "inflight_drain_observation_seconds",
                    round(observation_seconds, 6),
                    ">=",
                    observation_threshold,
                )
            )

        replacement_count = int(config["requests"]) - drain_count
        with concurrent.futures.ThreadPoolExecutor(max_workers=drain_count + 1) as executor:
            replacement_traffic = executor.submit(
                fixed_requests,
                replacement_address,
                replacement_count,
                int(config["concurrency"]),
                request_timeout,
            )
            draining = [
                executor.submit(
                    complete_draining_request, connection, index, shutdown_started
                )
                for index, connection in enumerate(drain_sockets)
            ]
            draining_samples = [future.result() for future in draining]
            replacement_samples, _ = replacement_traffic.result()
        drain_sockets.clear()
        for sample in replacement_samples:
            sample["sequence"] += drain_count
            sample["source_process"] = "replacement"
        old_shutdown = old.wait_for_shutdown(
            shutdown_started, float(config["thresholds"]["max_shutdown_seconds"])
        )
        samples = draining_samples + replacement_samples
        duration = time.perf_counter() - traffic_started
        metrics = request_metrics(samples, duration)
        metrics["draining_requests"] = drain_count
        metrics["replacement_requests"] = replacement_count
        metrics["inflight_drain_observation_seconds"] = round(observation_seconds, 6)
        violations.extend(load_thresholds(metrics, config["thresholds"]))
        if old_shutdown["forced"] or old_shutdown["exit_code"] != 0:
            violations.append(violation("old_process_exit_code", old_shutdown["exit_code"], "==", 0))
        if old_shutdown["duration_seconds"] > config["thresholds"]["max_shutdown_seconds"]:
            violations.append(
                violation(
                    "old_process_shutdown_seconds",
                    old_shutdown["duration_seconds"],
                    "<=",
                    config["thresholds"]["max_shutdown_seconds"],
                )
            )
        replacement_shutdown = replacement.signal_and_wait(
            float(config["thresholds"]["max_shutdown_seconds"])
        )
        if replacement_shutdown["forced"] or replacement_shutdown["exit_code"] != 0:
            violations.append(
                violation("replacement_process_exit_code", replacement_shutdown["exit_code"], "==", 0)
            )
    except Exception as error:
        violations.append(violation("scenario_exception", error.__class__.__name__, "==", None))
    finally:
        for connection in drain_sockets:
            connection.close()
        old.kill()
        replacement.kill()
    return {
        "id": "graceful_rollout",
        "status": "passed" if not violations else "failed",
        "started_at": started_at,
        "completed_at": utc_now(),
        "duration_seconds": round(time.perf_counter() - started, 6),
        "thresholds": config["thresholds"],
        "metrics": metrics,
        "old_process_shutdown": old_shutdown,
        "replacement_process_shutdown": replacement_shutdown,
        "violations": violations,
        "samples": samples,
    }


def run_contract(
    scenario: dict[str, Any], workspace: Path, output_dir: Path
) -> dict[str, Any]:
    started_at = utc_now()
    started = time.perf_counter()
    timeout = float(scenario["timeout_seconds"])
    steps = []
    violations = []
    for step in scenario["steps"]:
        remaining = timeout - (time.perf_counter() - started)
        if remaining <= 0:
            violations.append(violation("scenario_timeout", True, "==", False))
            break
        result = command_step(
            list(step["command"]), remaining, output_dir, f"{scenario['id']}-{step['id']}", workspace
        )
        result["id"] = step["id"]
        steps.append(result)
        if result["timed_out"]:
            violations.append(violation(f"{step['id']}.timed_out", True, "==", False))
            break
        if result["launch_error"] is not None:
            violations.append(
                violation(f"{step['id']}.launch_error", result["launch_error"], "==", None)
            )
            break
        if result["exit_code"] != 0:
            violations.append(violation(f"{step['id']}.exit_code", result["exit_code"], "==", 0))
            break
    duration = time.perf_counter() - started
    if duration > float(scenario["max_duration_seconds"]):
        violations.append(
            violation(
                "duration_seconds", duration, "<=", float(scenario["max_duration_seconds"])
            )
        )
    return {
        "id": scenario["id"],
        "status": "passed" if not violations else "failed",
        "started_at": started_at,
        "completed_at": utc_now(),
        "duration_seconds": round(duration, 6),
        "thresholds": {
            "max_duration_seconds": scenario["max_duration_seconds"],
            "successful_exit_code": 0,
        },
        "steps": steps,
        "violations": violations,
    }


def validate_configuration(config: dict[str, Any]) -> None:
    if config.get("schema_version") != SCHEMA_VERSION:
        raise ConfigurationError("unsupported scenario schema version")
    for scenario_id in SERVER_SCENARIOS:
        if scenario_id not in config:
            raise ConfigurationError(f"missing {scenario_id} configuration")
        if set(config[scenario_id]["suites"]) != {"smoke", "full"}:
            raise ConfigurationError("server scenarios must run in smoke and full suites")

    load = config["http_load"]
    soak = config["http_soak"]
    rollout = config["graceful_rollout"]
    positive = [
        load["warmup_requests"],
        load["requests"],
        load["concurrency"],
        load["request_timeout_seconds"],
        load["startup_timeout_seconds"],
        soak["duration_seconds"],
        soak["requests_per_second"],
        soak["concurrency"],
        soak["request_timeout_seconds"],
        soak["startup_timeout_seconds"],
        rollout["requests"],
        rollout["concurrency"],
        rollout["request_timeout_seconds"],
        rollout["startup_timeout_seconds"],
        load["thresholds"]["max_shutdown_seconds"],
        soak["thresholds"]["max_shutdown_seconds"],
        rollout["thresholds"]["max_shutdown_seconds"],
        rollout["thresholds"]["min_drain_observation_seconds"],
    ]
    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
        for value in positive
    ):
        raise ConfigurationError("counts and durations must be finite and positive")
    if soak["duration_seconds"] > 3600:
        raise ConfigurationError("soak duration exceeds the one-hour local bound")
    soak_requests = round(soak["duration_seconds"] * soak["requests_per_second"])
    if (
        load["concurrency"] > load["requests"]
        or soak["concurrency"] > soak_requests
        or rollout["concurrency"] >= rollout["requests"]
    ):
        raise ConfigurationError("concurrency cannot exceed request count")

    threshold_groups = [
        (load["thresholds"], "max_p95_latency_ms"),
        (soak["thresholds"], "max_p99_latency_ms"),
        (rollout["thresholds"], "max_p95_latency_ms"),
    ]
    for thresholds, latency_key in threshold_groups:
        error_rate = thresholds["max_error_rate"]
        latency = thresholds[latency_key]
        if (
            isinstance(error_rate, bool)
            or not isinstance(error_rate, (int, float))
            or not math.isfinite(error_rate)
            or not 0 <= error_rate <= 1
        ):
            raise ConfigurationError("error-rate thresholds must be between zero and one")
        if (
            isinstance(latency, bool)
            or not isinstance(latency, (int, float))
            or not math.isfinite(latency)
            or latency <= 0
        ):
            raise ConfigurationError("latency thresholds must be finite and positive")
    if (
        rollout["thresholds"]["min_drain_observation_seconds"] * 1000
        > rollout["thresholds"]["max_p95_latency_ms"]
    ):
        raise ConfigurationError("drain observation exceeds the rollout latency budget")
    if load["thresholds"]["min_requests_per_second"] <= 0:
        raise ConfigurationError("load throughput threshold must be positive")
    if (
        soak["thresholds"]["min_requests_per_second"] <= 0
        or soak["thresholds"]["max_rss_growth_bytes"] <= 0
    ):
        raise ConfigurationError("soak thresholds must be positive")
    if rollout["thresholds"]["max_shutdown_seconds"] <= 0:
        raise ConfigurationError("rollout shutdown threshold must be positive")

    build = config["build"]
    if (
        not build.get("command")
        or not all(isinstance(part, str) and part for part in build["command"])
        or build["timeout_seconds"] <= 0
    ):
        raise ConfigurationError("build command and deadline must be valid")

    identifiers = []
    for scenario in config.get("contract_scenarios", []):
        scenario_id = scenario["id"]
        identifiers.append(scenario_id)
        if RUN_ID.fullmatch(scenario_id) is None:
            raise ConfigurationError("contract scenario ID is not artifact-safe")
        if scenario["timeout_seconds"] <= 0 or scenario["max_duration_seconds"] <= 0:
            raise ConfigurationError("contract deadlines must be positive")
        if scenario["max_duration_seconds"] > scenario["timeout_seconds"]:
            raise ConfigurationError("contract duration threshold exceeds its hard timeout")
        if "full" not in scenario["suites"] or not set(scenario["suites"]) <= {"smoke", "full"}:
            raise ConfigurationError("contract suites must be known and include full")
        if not scenario.get("steps"):
            raise ConfigurationError("contract scenario must contain at least one step")
        step_ids = []
        for step in scenario["steps"]:
            step_ids.append(step["id"])
            if RUN_ID.fullmatch(step["id"]) is None:
                raise ConfigurationError("contract step ID is not artifact-safe")
            if not step.get("command") or not all(
                isinstance(part, str) and part for part in step["command"]
            ):
                raise ConfigurationError("contract commands must be nonempty string arrays")
        if len(step_ids) != len(set(step_ids)):
            raise ConfigurationError("contract step IDs must be unique")
    if len(identifiers) != len(set(identifiers)):
        raise ConfigurationError("contract scenario IDs must be unique")
    if set(identifiers) != CONTRACT_SCENARIOS:
        raise ConfigurationError("contract scenario set is incomplete")


def selected_scenarios(config: dict[str, Any], suite: str, requested: list[str]) -> list[str]:
    contracts = {scenario["id"]: scenario for scenario in config["contract_scenarios"]}
    available = SERVER_SCENARIOS | set(contracts)
    if requested:
        unknown = set(requested) - available
        if unknown:
            raise ConfigurationError(f"unknown scenarios: {', '.join(sorted(unknown))}")
        selected = set(requested)
    else:
        selected = {
            scenario_id
            for scenario_id in SERVER_SCENARIOS
            if suite in config[scenario_id]["suites"]
        }
        selected.update(
            scenario["id"]
            for scenario in config["contract_scenarios"]
            if suite in scenario["suites"]
        )
    return [scenario_id for scenario_id in SCENARIO_ORDER if scenario_id in selected]


def compact_result(result: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    artifact = output_dir / f"{result['id']}.json"
    write_json(artifact, result)
    compact = dict(result)
    compact.pop("samples", None)
    compact["result_artifact"] = artifact.name
    return compact


def blocked_result(scenario_id: str) -> dict[str, Any]:
    return {
        "id": scenario_id,
        "status": "failed",
        "started_at": utc_now(),
        "completed_at": utc_now(),
        "duration_seconds": 0.0,
        "thresholds": {},
        "violations": [violation("server_setup", "unavailable", "==", "ready")],
    }


def exception_result(scenario_id: str, error: Exception) -> dict[str, Any]:
    return {
        "id": scenario_id,
        "status": "failed",
        "started_at": utc_now(),
        "completed_at": utc_now(),
        "duration_seconds": 0.0,
        "thresholds": {},
        "violations": [
            violation("scenario_exception", error.__class__.__name__, "==", None)
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=("smoke", "full"), default="smoke")
    parser.add_argument("--scenario", action="append", default=[])
    parser.add_argument("--soak-seconds", type=float)
    parser.add_argument("--server-bin", type=Path)
    parser.add_argument("--run-id")
    return parser.parse_args()


def artifact_io_failure(run_id: str, error: OSError) -> int:
    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "run_id": run_id,
                "status": "failed",
                "error": "artifact_io",
                "error_type": error.__class__.__name__,
            },
            sort_keys=True,
        )
    )
    return 2


def main() -> int:
    args = parse_args()
    workspace = Path(__file__).resolve().parents[2]
    config_path = Path(__file__).with_name("scenarios.json")
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise ConfigurationError("scenario configuration must be an object")
        config = copy.deepcopy(config)
        if args.soak_seconds is not None:
            config["http_soak"]["duration_seconds"] = args.soak_seconds
        validate_configuration(config)
        selected = selected_scenarios(config, args.suite, args.scenario)
    except (OSError, KeyError, TypeError, json.JSONDecodeError, ConfigurationError) as error:
        print(
            json.dumps(
                {"schema_version": SCHEMA_VERSION, "status": "invalid", "error": error.__class__.__name__},
                sort_keys=True,
            )
        )
        return 2

    run_id = args.run_id or f"{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{os.getpid()}"
    if RUN_ID.fullmatch(run_id) is None or run_id in {".", ".."}:
        print(json.dumps({"schema_version": SCHEMA_VERSION, "status": "invalid", "error": "run_id"}))
        return 2
    output_dir = workspace / "target" / "performance" / run_id
    try:
        output_dir.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        print(
            json.dumps(
                {"schema_version": SCHEMA_VERSION, "status": "invalid", "error": error.__class__.__name__},
                sort_keys=True,
            )
        )
        return 2

    try:
        effective = {
            "schema_version": SCHEMA_VERSION,
            "suite": args.suite,
            "selected_scenarios": selected,
            "configuration": config,
        }
        write_json(output_dir / "effective-config.json", effective)
        summary: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "artifact_directory": str(output_dir.relative_to(workspace)),
            "suite": args.suite,
            "status": "running",
            "started_at": utc_now(),
            "completed_at": None,
            "machine": machine_metadata(),
            "selected_scenarios": selected,
            "effective_configuration_artifact": "effective-config.json",
            "setup": {},
            "scenarios": [],
            "violations": [],
        }
        write_json(output_dir / "summary.json", summary)
    except OSError as error:
        return artifact_io_failure(run_id, error)

    server_required = bool(SERVER_SCENARIOS.intersection(selected))
    server_ready = not server_required
    server_binary: Optional[Path] = None
    if server_required:
        if args.server_bin is not None:
            server_binary = args.server_bin
            if not server_binary.is_absolute():
                server_binary = workspace / server_binary
            server_binary = server_binary.resolve()
            server_ready = server_binary.is_file() and os.access(server_binary, os.X_OK)
            summary["setup"]["server_binary"] = {
                "path": str(server_binary),
                "provided": True,
                "status": "passed" if server_ready else "failed",
            }
        else:
            try:
                build = command_step(
                    list(config["build"]["command"]),
                    float(config["build"]["timeout_seconds"]),
                    output_dir,
                    "build-server",
                    workspace,
                )
            except OSError as error:
                return artifact_io_failure(run_id, error)
            build["status"] = (
                "passed"
                if build["exit_code"] == 0 and not build["timed_out"] and build["launch_error"] is None
                else "failed"
            )
            summary["setup"]["server_build"] = build
            server_binary = (workspace / "target" / "release" / "omnius-server").resolve()
            server_ready = build["status"] == "passed" and server_binary.is_file()

    contracts = {scenario["id"]: scenario for scenario in config["contract_scenarios"]}
    for scenario_id in selected:
        print(f"running {scenario_id}", file=sys.stderr, flush=True)
        try:
            if scenario_id in SERVER_SCENARIOS and not server_ready:
                result = blocked_result(scenario_id)
            elif scenario_id == "http_load":
                result = run_http_load(server_binary, workspace, output_dir, config[scenario_id])
            elif scenario_id == "http_soak":
                result = run_http_soak(server_binary, workspace, output_dir, config[scenario_id])
            elif scenario_id == "graceful_rollout":
                result = run_graceful_rollout(
                    server_binary, workspace, output_dir, config[scenario_id]
                )
            else:
                result = run_contract(contracts[scenario_id], workspace, output_dir)
        except Exception as error:
            result = exception_result(scenario_id, error)
        try:
            compact = compact_result(result, output_dir)
            summary["scenarios"].append(compact)
            for item in result["violations"]:
                summary["violations"].append({"scenario": scenario_id, **item})
            write_json(output_dir / "summary.json", summary)
        except OSError as error:
            return artifact_io_failure(run_id, error)

    summary["status"] = "passed" if not summary["violations"] else "failed"
    summary["completed_at"] = utc_now()
    try:
        write_json(output_dir / "summary.json", summary)
    except OSError as error:
        return artifact_io_failure(run_id, error)
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
