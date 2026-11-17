#!/usr/bin/env python3
"""Source policy regression cases; run with the full aggregate source gate.

No worker socket, Podman store, Forgejo endpoint, or native job is touched.
"""
import importlib.util
import json
import unittest
from copy import deepcopy
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "src/main/resources/runtime/forgejo_ci_socket_guard.py"
spec = importlib.util.spec_from_file_location("forgejo_ci_guard_policy", SOURCE)
guard_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard_module)


class CreatePolicy(unittest.TestCase):
    def setUp(self):
        self.guard = guard_module.Guard.__new__(guard_module.Guard)
        self.guard.image = "localhost/reviewed@sha256:" + "a" * 64
        self.guard.image_id = "sha256:" + "b" * 64
        self.guard.network = "p0v3-ci-q-0123456789ab-internal"
        self.guard.ca_mount = "/home/webservices-lab-ci-runner/.local/share/p0v3-ci/q-0123456789ab/transport-ca.pem:/etc/ssl/certs/p0v3-ci-forgejo-ca.pem:ro"
        self.guard.memory = 2 * 1024 * 1024 * 1024
        self.create = {
            "Image": self.guard.image, "User": "1000:1000", "WorkingDir": "/workspace",
            "Cmd": ["/bin/sh", "-ec", "true"], "Env": ["PATH=/usr/bin:/bin"] + [
                name + "=/etc/ssl/certs/p0v3-ci-forgejo-ca.pem" for name in
                ("SSL_CERT_FILE", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE")],
            "HostConfig": {
                "NetworkMode": self.guard.network, "Memory": self.guard.memory,
                "MemorySwap": self.guard.memory, "NanoCpus": 2_000_000_000,
                "PidsLimit": 256, "CapDrop": ["ALL"], "Binds": [self.guard.ca_mount],
                "SecurityOpt": ["no-new-privileges"], "Privileged": False,
            },
        }

    def deny(self, section, field, value):
        candidate = deepcopy(self.create)
        candidate[section][field] = value
        with self.assertRaises(ValueError, msg=f"{section}.{field}"):
            self.guard.validate_create(candidate)

    def test_minimal_reviewed_process_and_resources(self):
        self.guard.validate_create(self.create)

    def test_no_extra_docker_authority_even_when_boolean_false_or_empty(self):
        for field, value in {
            "PidMode": "host", "IpcMode": "host", "UsernsMode": "host",
            "CgroupnsMode": "host", "UTSMode": "host", "Devices": ["/dev/kvm"],
            "DeviceRequests": [{"Capabilities": [["gpu"]]}],
            "VolumesFrom": ["other"], "CapAdd": ["SYS_ADMIN"],
            "SecurityOpt": ["no-new-privileges", "seccomp=unconfined"],
            "Dns": ["8.8.8.8"], "ExtraHosts": ["host.internal:127.0.0.1"],
            "CgroupParent": "../../system.slice", "Sysctls": {},
            "Mounts": [{"Source": "/", "Target": "/host"}],
            "Binds": ["/run/user/784/podman/podman.sock:/run/engine.sock"],
            "MemorySwap": -1, "NanoCpus": 0,
            "PublishAllPorts": True, "PortBindings": {"443/tcp": [{}]},
        }.items():
            self.deny("HostConfig", field, value)
        for field, value in {
            "NetworkingConfig": {}, "ExposedPorts": {}, "Entrypoint": ["/bin/sh"],
            "Volumes": {}, "NetworkDisabled": False,
        }.items():
            candidate = deepcopy(self.create)
            candidate[field] = value
            with self.assertRaises(ValueError, msg=field):
                self.guard.validate_create(candidate)

    def test_private_ca_must_be_inherited_by_checkout_and_artifact_steps(self):
        for key in ("SSL_CERT_FILE", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE"):
            candidate = deepcopy(self.create)
            candidate["Env"] = [value for value in candidate["Env"] if not value.startswith(key + "=")]
            with self.assertRaises(ValueError, msg=key):
                self.guard.validate_create(candidate)
            candidate["Env"].append(key + "=/etc/ssl/certs/host-ca.pem")
            with self.assertRaises(ValueError, msg=key):
                self.guard.validate_create(candidate)

    def test_no_privileged_labels_or_host_credentials(self):
        for label in ("io.containers.autoupdate", "io.podman.annotations", "org.opencontainers.image.ref.name"):
            candidate = deepcopy(self.create)
            candidate["Labels"] = {label: "image"}
            with self.assertRaises(ValueError):
                self.guard.validate_create(candidate)
        for key in ("DOCKER_HOST", "CONTAINER_HOST", "FORGEJO_RUNNER_TOKEN",
                    "AWS_SECRET", "DATABASE_PASSWORD", "PRIVATE_KEY", "HTTP_PROXY",
                    "ACTIONS_RESULTS_URL"):
            candidate = deepcopy(self.create)
            candidate["Env"].append(f"{key}=unsafe")
            with self.assertRaises(ValueError, msg=key):
                self.guard.validate_create(candidate)

    def test_native_readback_must_match_namespace_device_and_security_contract(self):
        cid = "c" * 64
        self.guard.requested = self.create
        detail = {
            "Id": cid, "Image": self.guard.image_id,
            "Config": {"Image": self.guard.image, "User": "1000:1000", "Env": self.create["Env"]},
            "HostConfig": {
                **self.create["HostConfig"], "Devices": [], "DeviceRequests": [],
                "VolumesFrom": [], "CapAdd": [], "Binds": [self.guard.ca_mount], "Mounts": [],
                "ShmSize": 67_108_864, "Privileged": False,
            },
            "Mounts": [{"Source": self.guard.ca_mount.split(':')[0],
                        "Destination": "/etc/ssl/certs/p0v3-ci-forgejo-ca.pem", "RW": False}],
            "NetworkSettings": {"Networks": {self.guard.network: {}}, "Ports": {}},

            "State": {"Running": False, "Pid": 0},
        }
        self.guard.request = lambda *_args: (200, json.dumps(detail).encode(), ())
        self.assertEqual(self.guard.inspect(cid), detail)
        for target, field, value in (
            ("HostConfig", "PidMode", "host"), ("HostConfig", "IpcMode", "host"),
            ("HostConfig", "UsernsMode", "host"), ("HostConfig", "Devices", [{"PathOnHost": "/dev/kvm"}]),
            ("HostConfig", "CapAdd", ["SYS_ADMIN"]),
            ("HostConfig", "Binds", [self.guard.ca_mount, "/run/user/784/podman/podman.sock:/run/engine.sock"]),
            ("HostConfig", "SecurityOpt", ["no-new-privileges", "seccomp=unconfined"]),
            ("HostConfig", "MemorySwap", -1), ("NetworkSettings", "Ports", {"443/tcp": [{}]}),
            ("NetworkSettings", "Networks", {
                self.guard.network: {}, "bridge": {"IPAddress": "10.0.0.8"}}),
        ):
            changed = deepcopy(detail)
            changed[target][field] = value
            self.guard.request = lambda *_args, snapshot=changed: (200, json.dumps(snapshot).encode(), ())
            with self.assertRaises(ValueError, msg=field):
                self.guard.inspect(cid)


if __name__ == "__main__":
    unittest.main()
