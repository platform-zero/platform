"""Fail-closed Matrix/RTC recovery observations. No timeout or cleanup authorizes source resume."""


def require_target_stopped(processes, observations, deployment):
    """Require exact owned container readback, not a stop command exit or a partial list."""
    if not processes or set(observations) != set(processes):
        raise ValueError("Incomplete target isolation readback")
    for process, item in observations.items():
        labels = item.get("Config", {}).get("Labels", {})
        state = item.get("State", {})
        if (labels.get("io.p0v3.private-deployment") != deployment
                or item.get("Name", "").lstrip("/") != "p0v3-live-" + deployment + "-" + process
                or not item.get("Id") or state.get("Running") is not False
                or state.get("Paused") is True or state.get("Restarting") is True
                or state.get("Status") not in ("exited", "stopped", "created")
                or state.get("Pid") != 0):
            raise ValueError("Target not verifiably isolated")
    return {process: item["Id"] for process, item in observations.items()}


def require_source_unchanged(before, after):
    if not before or set(before) != set(after):
        raise ValueError("Incomplete source observation")
    for process, original in before.items():
        current = after[process]
        if (original.get("Id") != current.get("Id")
                or original["State"]["StartedAt"] != current["State"]["StartedAt"]
                or original["State"].get("Running") is not False
                or current["State"].get("Running") is not False):
            raise ValueError("Source changed during isolated restore")
