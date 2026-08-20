# `host_vars/` — per-host configuration

Ansible loads `host_vars/<inventory_hostname>.yml` for each host listed in
`inventory.yml`. Those files describe **your** machines: addresses, NIC MAC
addresses, disk layout, mesh IPs. They are infrastructure identity, so
`host_vars/*.yml` is git-ignored (see `../.gitignore`) — exactly like
`inventory.yml` and `terraform.tfvars`.

The two `*.example.yml` files here are tracked and document the full schema:

| File | For hosts in group | Copy to |
| --- | --- | --- |
| `cc-node.example.yml` | `cc_nodes` (trusted control plane) | `host_vars/<your-cc-hostname>.yml` |
| `miner.example.yml` | `miner_nodes` (untrusted miner fleet) | `host_vars/<your-miner-hostname>.yml` |

```sh
cp host_vars/miner.example.yml host_vars/my-miner-1.yml
$EDITOR host_vars/my-miner-1.yml
```

Ansible ignores the `*.example.yml` files themselves: it only reads the file
whose basename matches an inventory hostname.

## Schema

### Both groups

| Key | Type | Meaning |
| --- | --- | --- |
| `ansible_host` | string | Address Ansible connects to (public IP for the first run; a mesh address afterwards). |
| `ansible_user` | string | SSH login user. Must be able to `sudo` without a password (`ansible.cfg` sets `become: true`). |
| `ansible_ssh_private_key_file` | path | Operator-local SSH private key. Never committed. |

### `cc_nodes` only

| Key | Type | Meaning |
| --- | --- | --- |
| `privnet_static_ip` / `privnet_static_prefix` / `privnet_static_cidr` | string / int / string | Static address the host takes on the cluster's private L2 segment. `03-private-network.yml` writes it into netplan. |
| `privnet_bond_name` | string | Name of the LACP bond interface it creates. |
| `privnet_bond_macs` | list[string] | **Permanent** MACs (`ethtool -P`) of the private-segment NICs to enslave. The playbook refuses to enslave the default-route NIC. |
| `privnet_bond_mode` / `privnet_bond_lacp_rate` / `privnet_bond_xmit_hash_policy` | string | netplan bond parameters. |
| `data_raid_devices` | list[path] | Raw, EMPTY block devices for the mdadm data array. **Verify with `lsblk` before the first run** — `04-data-raid.yml` fails closed on unrecognised data, but do not rely on that. |
| `data_raid_name` / `data_raid_level` / `data_raid_filesystem` | string / int / string | mdadm array parameters. |

### `miner_nodes` only

| Key | Type | Meaning |
| --- | --- | --- |
| `cpu_model_expected` | string | Asserted by `00-preflight.yml` against `/proc/cpuinfo`. Must be an SEV-SNP capable AMD EPYC. |
| `ram_gb_expected` | int | Preflight asserts `>=` this. |
| `orders_bind_ip` | string | This miner's **own** NetBird mesh address. The miner-agent's signed-order HTTP server binds it and ONLY it. Assigned by NetBird at mesh join, so it is necessarily per-host. Until you set it, the `group_vars/miner_nodes.yml` placeholder is used and the server fails to bind. |
| `host_cvm.cpu_budget` / `host_cvm.memory_mb_budget` | int | CPU threads and MiB the host offers to tenant CVMs. A **reservation**, not the whole machine — leave headroom for the host OS and the agent. |
| `nvme_system_devices` | list[path] | The boot/system disks. Preflight asserts the playbook never formats these. |
| `nvme_data_devices` | list[path] | Extra raw disks for tenant volumes; `[]` if the box has none. |
| `netbird_setup_key_file` | string | **Filename only**, resolved under `operator_secret_dir` (`~/.config/hippius` by default) on the *operator workstation*. The key itself is never committed and never stored on the miner. |

## Rules

- Never commit a real `host_vars/<hostname>.yml`.
- Never put a secret in one. Secrets are read at run time from
  `operator_secret_dir` — see `../README.md` § Secrets.
- Re-check the disk lists with `lsblk` on the actual box before the first
  run. A wrong `nvme_*` list is the one mistake these playbooks cannot
  undo for you.
