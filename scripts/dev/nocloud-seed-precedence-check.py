#!/usr/bin/env python3
"""Drive the REAL cloud-init NoCloud datasource against an untrusted-miner
fixture and report whose seed wins.

Used by `tenant-image-bake-m0-harden-test.sh`. The only thing replaced is
hardware access: the SMBIOS read, the kernel cmdline, the block-device
scan and the mount. `DataSourceNoCloud._get_data` itself runs unmodified,
fed the `99-hippius-nocloud.cfg` the bake writes.

The miner controls everything outside the SNP launch measurement, so the
fixture plays it both ways cloud-init would listen:
  - a `cidata`-labelled disk carrying attacker user-data + meta-data
    (an ssh key and a fresh instance-id, so cloud-init re-provisions);
  - an SMBIOS system-serial-number of `ds=nocloud;s=file://<attacker>/`.
The legitimate seed is the tmpfs dir the initramfs fills from the KBS
release, reached via the pinned `seedfrom: /run/cloud-init/seed/`.

Prints one JSON object on stdout; the caller asserts on it:
  attacker_in_metadata  attacker ssh key / instance-id reached meta-data
  attacker_in_userdata  attacker user-data survived
  cidata_probed         cloud-init scanned block devices for a label
  seedfrom_read         the seed path(s) util.read_seeded was asked for
  claimed               _get_data returned True
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml
from cloudinit import dmi, helpers, util
from cloudinit.sources import DataSourceNoCloud

SEED_PATH = "/run/cloud-init/seed/"
# The measured guest cmdline carries this token (see the bake's UKI /
# golden cmdline); cloud-init parses it on every boot.
MEASURED_CMDLINE = f"console=ttyS0 ro ds=nocloud;s={SEED_PATH}"
ATTACKER_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATTACKERATTACKERATTACKERATTACKERATTACK miner"
ATTACKER_IID = "iid-miner-reprovision"
ATTACKER_UD = "#cloud-config\nruncmd:\n  - [ sh, -c, 'echo owned > /root/owned' ]\n"
LEGIT_IID = "iid-tenant-legit"
LEGIT_UD = "#cloud-config\nhostname: tenant\n"


def write_seed(root: Path, user_data: str, meta_data: dict[str, Any]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "user-data").write_text(user_data)
    (root / "meta-data").write_text(yaml.safe_dump(meta_data))
    return root


def main(cfg_path: str) -> int:
    sys_cfg: dict[str, Any] = yaml.safe_load(Path(cfg_path).read_text()) or {}

    with tempfile.TemporaryDirectory(prefix="nocloud-precedence-") as tmp:
        work = Path(tmp)
        legit = write_seed(
            work / "legit-seed",
            LEGIT_UD,
            {"instance-id": LEGIT_IID, "local-hostname": "tenant"},
        )
        attacker_disk = write_seed(
            work / "attacker-cidata",
            ATTACKER_UD,
            {"instance-id": ATTACKER_IID, "public-keys": [ATTACKER_KEY]},
        )
        attacker_url = write_seed(
            work / "attacker-dmi-url",
            ATTACKER_UD,
            {"instance-id": ATTACKER_IID, "public-keys": [ATTACKER_KEY]},
        )

        probed: list[str] = []
        seedfrom_read: list[str] = []
        real_read_seeded = util.read_seeded

        def fake_dmi(key: str) -> str | None:
            if key == "system-serial-number":
                return f"ds=nocloud;s=file://{attacker_url}/"
            return None

        def fake_read_seeded(base: str, *args: Any, **kwargs: Any) -> Any:
            seedfrom_read.append(base)
            # The pinned tmpfs path is redirected to the fixture's legit
            # seed; anything else (an attacker URL) is read as given.
            target = f"{legit}/" if base == SEED_PATH else base
            return real_read_seeded(target, *args, **kwargs)

        def fake_get_devices(_self: Any, label: str) -> list[str]:
            probed.append(label)
            return ["/dev/vde"] if label.lower() == "cidata" else []

        def fake_mount_cb(dev: str, callback: Any, data: Any) -> Any:
            if dev != "/dev/vde":
                raise util.MountFailedError(dev)
            return callback(str(attacker_disk), data)

        dmi.read_dmi_data = fake_dmi
        util.get_cmdline = lambda: MEASURED_CMDLINE
        util.read_seeded = fake_read_seeded
        util.mount_cb = fake_mount_cb
        DataSourceNoCloud.DataSourceNoCloud._get_devices = fake_get_devices

        paths = helpers.Paths(
            {
                "cloud_dir": str(work / "cloud"),
                "run_dir": str(work / "run"),
                "seed_dir": str(work / "cloud" / "seed"),
            }
        )
        ds = DataSourceNoCloud.DataSourceNoCloud(sys_cfg, None, paths)
        claimed = bool(ds._get_data())

        metadata: dict[str, Any] = ds.metadata or {}
        userdata = ds.userdata_raw or ""
        if isinstance(userdata, bytes):
            userdata = userdata.decode()
        report = {
            "claimed": claimed,
            "instance_id": metadata.get("instance-id"),
            "attacker_in_metadata": ATTACKER_KEY in json.dumps(metadata)
            or metadata.get("instance-id") == ATTACKER_IID,
            "attacker_in_userdata": "owned" in userdata,
            "legit_userdata": userdata == LEGIT_UD,
            "cidata_probed": probed,
            "seedfrom_read": seedfrom_read,
            "ds_cfg_fs_label": ds.ds_cfg.get("fs_label", "<unset: cidata default>"),
        }
        print(json.dumps(report))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2 or not os.path.isfile(sys.argv[1]):
        print("usage: nocloud-seed-precedence-check.py <99-hippius-nocloud.cfg>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
