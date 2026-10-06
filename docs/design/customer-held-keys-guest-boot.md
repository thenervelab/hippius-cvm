# Customer-held keys: what the guest does at boot (H5 / H5b)

This note covers the guest side of customer-held disk keys, M1 (`split`)
and M2 (`customer`), as implemented in
`scripts/initramfs/hippius-golden-overlay.sh` and
`binaries/guest-release`. M0 (`hippius`, or no `hippius.key_mode` token)
is unchanged by everything below except the cmdline-length rule.

## 1. cloud-init user-data reaches the guest on the first boot only (H5b)

**Why.** In M0 the initramfs writes the KBS-released user-data (minted by
vali) into the NoCloud seed on `/run/cloud-init/seed/` with a random
instance-id on every boot. cloud-init therefore treats every boot as a new
instance and re-runs its per-instance modules (`users`, `ssh`,
`write_files`, `runcmd`, ...) as root, after the disk is unlocked. For M1
and M2 that would let a compromised Hippius run code in the unlocked guest
on any later boot, and so read the plaintext the customer's key share is
meant to protect.

**What the guest does for M1/M2.**

- The instance-id is stable for the life of the VM: `iid-` followed by the
  first 32 lowercase hex characters of
  `SHA-256("hippius-iid-v1\0" ‖ vm_id)`. `hippius-guest-release
  --instance-id-out` derives it from the ticket's `vm_id`, the same
  `vm_id` the keyslot key is combined under, so a boot under another
  `vm_id` opens nothing.
- The release writes the user-data to a tmpfs staging file
  (`/run/hippius/userdata.staged`), not to the seed. The release happens
  before the overlay upper is opened, and only after the upper is opened
  do we know whether this boot formatted it.
- The boot that formats the upper (a blank disk, or an interrupted first
  boot formatted again under a KBS expectation of 0) moves the staged
  user-data into the seed.
- Every other boot shreds the staged file and gives cloud-init an empty
  `user-data` with the same instance-id.
- The decision fails closed. Only `hippius_golden_format_upper` sets the
  first-boot flag. The flag is reset when the library is sourced, and it
  is never read from the environment (unknown
  `key=value` words on the kernel cmdline become initramfs environment
  variables). Any other state, including a boot that fails anywhere
  before the overlay is mounted, means the user-data does not reach the
  seed.

**What cloud-init does with that.** Checked with the real cloud-init on
Ubuntu 24.04 (26.1), Debian 13 (25.1.4) and Fedora 43 (25.2) by
`scripts/dev/cloud-init-first-boot-only-check.sh`:

- A later boot with the same instance-id and an empty user-data runs
  nothing from that boot's user-data. The per-instance modules are
  skipped (their semaphores are on the encrypted upper). The per-boot ones
  (`bootcmd`, boothooks, `set_hostname`, `growpart`, ...) see an empty
  cloud-config, and the first boot's `bootcmd` does not run again. The
  tenant's user, its `authorized_keys` and the ssh host key are kept, and
  cloud-init reports no error.
- What the first boot's user-data installed for later boots does still
  run: a `text/x-shellscript-per-boot` part is written to
  `/var/lib/cloud/scripts/per-boot` and `scripts_per_boot` runs it on every
  boot. The same goes for anything a first-boot `runcmd` puts in place,
  such as a systemd unit. That is part of the first-boot exposure below;
  H5b stops new content on later boots, not what the first boot left
  behind.
- The same instance-id with a non-empty user-data still runs that
  user-data's `bootcmd` and boothooks as root, on every boot. So "same
  instance" alone is not enough: the later-boot user-data has to be empty.
- NoCloud reads the seed fresh on every boot. It does not restore the
  previous boot's user-data from its cache, because its quick instance
  check only looks at `/var/lib/cloud/seed/nocloud*`, and that directory
  does not exist on a golden VM.

**What stays exposed, by decision D1.**

- The first boot. vali mints the first-boot user-data, and a compromised
  Hippius can put anything in it, including code that runs again on
  every later boot (see above). v1.1 moves the NetBird setup key into a
  separate KBS secret and lets the guardian pin the user-data digest.
  Until then, customer-facing copy must not say "a compromised Hippius
  cannot decrypt" without "except at first boot".
- Blanking the upper. Zeroing the LUKS header of a VM that has already
  booted does NOT give a first boot. Without further gates it would be
  dangerous: the guardian would seal the VM's active share (a blank upper
  sends no share version), the guest would format under the same KEK,
  and the first-boot user-data would run as root and could rebuild that
  KEK to open a copy of the old upper. Three gates, M1/M2 only:
  - the guest formats a blank upper only when the signed expectation E
    (the KBS's in M1, the guardian's in M2) is exactly 0, i.e. the VM has
    never confirmed a boot. E > 0 or no E fails closed;
  - `cryptsetup isLuks` must say "not LUKS" (exit 1); any other error
    fails closed instead of reading as blank;
  - the anti-rollback gate refuses "no stamp, E > 0" (the M0 legacy
    migration) and a boot with no expectation at all.
  One classification, made before any contact, is authoritative.
  `hippius_golden_keymode_prepare` puts the upper in exactly one class,
  held in a shell variable (never read from the environment):
  - ready: LUKS with a valid token. The token's share version is sent,
    and the upper is only reopened. If it looks blank, init-labelled or
    unreadable by the time it is opened, the boot fails closed. Otherwise
    a host could keep the token so a version is sent, then flip the
    unauthenticated label or zero the header after the release.
  - blank: no LUKS header.
  - init: the init label, token or not.

  For blank and init no share version is sent, and the format needs that
  version-less release AND E = 0. Only that path sets the first-boot flag
  and installs user-data. Its stamp confirm is mandatory: 5 attempts with
  backoff, then the boot fails closed before the seed is installed. A
  dropped confirm therefore cannot leave E at 0 behind a provisioned
  volume. On later boots, and in M0, the confirm stays non-fatal.
  With stamp protocol v2 (#1320), which applies to M0 and M1:
  - In M1, E is the v2 KBS expectation. A first boot at E = 0 adopts the
    fresh timeline the KBS issues (`zero → T_fresh`), stamps
    `(T_fresh, 1)`, and must confirm it.
  - A KBS store wipe also puts a live VM back at E = 0 on a fresh
    timeline. A ready upper then just reopens and adopts it; the ready
    class never formats. A blanked or init upper at that point meets the
    guardian's once-only version-less gate, which is the layer that holds
    there.
  - M2 stays on the v1 gate with the guardian's stamp. That gate still
    refuses a timeline-bound volume at every E.
  - Neither gate performs the one-time "no stamp" legacy migration for
    M1/M2.

  In M1 a compromised Hippius signs the KBS response and so can forge
  E = 0. The second layer is the guardian: it seals for "no share
  version" once per VM, and only `guardian approve-reinit` allows it
  again. A genuine first boot, or an approved re-init, formats with a
  fresh in-guest master key.
- A crash in the first-boot window. A host reset after the upper is
  marked ready but before cloud-init has applied the first-boot user-data
  leaves a VM whose later boots get none of it: no tenant key, no NetBird.
  The same happens when the first-boot stamp confirm never lands. The
  volume holds only first-boot state at that point, so relaunch it.

**cloud-init directives on the cmdline are refused.** cloud-init and
its `ds-identify` generator read `/proc/cmdline` on every boot, and some
of that input is configuration or code. The cmdline is measured but vali
mints it, so for M1/M2 `GuardianBinding::from_cmdline` in hippius-types
refuses these, and so do the guardian and the guest, which share that
parser. vali refuses them at mint time too (H6a). The check covers
cloud-init 22.4.2 (Debian 12), 24.4 (CentOS Stream 10), 25.1.4 (Debian 13),
25.2 (Fedora 43) and 26.1 (Ubuntu 24.04). It refuses:

- `cc:` and `end_cc` anywhere, as substrings. The config between them is
  merged into the system config, and up to 25.x cloud-init finds `cc:`
  even inside another token: on Debian 12, `hippius.vm_id=acc:…end_cc`
  is read;
- tokens whose key (the part before the first `=`) is `url`,
  `cloud-config-url` (fetched as cloud-config), `network-config` (base64
  network config, preferred over every other source) or starts with
  `ci.` (`ci.ds`, `ci.datasource`, `ci.di.policy`, ...). cloud-init and
  `ds-identify` split on whitespace and key on the first `=`, so
  `hippius.kbs_url=` is not `url=`;
- a `ds=` token other than `ds=nocloud`, `ds=nocloud-net`, or either of
  those followed by `;s=/run/cloud-init/seed/`. Those four are harmless:
  they select the datasource the bake already pins, and the bake's
  `seedfrom` overrides `s=`. Any other `ds=` value is refused. That
  covers another datasource, and NoCloud meta-data such as `i=`
  (instance-id), `h=` (hostname) or arbitrary keys like `public-keys`.

Not refused, because they cannot hand cloud-init content:
- `ip=`, which only makes cloud-init read `/run/net-*.conf`, and that is
  owned by the measured initramfs;
- `root=` and `net.ifnames=`;
- `cloud-init=disabled` and the `scaleway`/`vultr` markers, which at worst
  cause a denial of service.

M0 cmdlines, which carry no grammar key, are not checked.

## 2. A cmdline that may have been truncated is refused

SEV measures the whole cmdline, but the guest only sees part of a long
one:

- The x86 kernel keeps at most 2047 bytes (`COMMAND_LINE_SIZE` = 2048
  with the NUL).
- The EFI stub (`efi_convert_cmdline`), which is the path OVMF direct
  boot takes, cuts at the last whitespace before byte 2048.
- Both limits apply to the string the kernel receives, which is longer
  than the measured one. OVMF's QEMU direct-kernel loader puts
  `initrd=initrd ` (14 bytes) in front of the cmdline whenever an initrd
  is present. That is edk2 `GenericQemuLoadImageLib`, the
  `QemuLoadImageLib` of `OvmfPkg/AmdSev/AmdSevX64.dsc`, at our pinned
  edk2-stable202511 (`packer/ovmf/inputs.lock`): it formats the load
  options as `"%a%a%a", "", "initrd=initrd ", CommandLine`.
- The kernel-hashes check covers only the fw_cfg cmdline blob, so the
  measurement excludes the prefix and `/proc/cmdline` includes it.

If a `hippius.key_mode=` token is cut off, an M1 or M2 launch looks like
M0 from inside the guest: the guest would skip the guardian and format its
first-boot volume under the KBS KEK alone.

**Rule.** `hippius-guest-release` refuses, before any contact, a
`/proc/cmdline` (prefix included, trailing newline not counted) that is at
least 2022 bytes long and carries no `hippius.key_mode` token.

- 2022 is 2047 minus the length of the longest key-mode token
  (`hippius.key_mode=customer`, 25 bytes). For the stub to cut the token
  itself off, the token must have started within its own length of the
  limit, so at least 2022 bytes survive. The kernel's own bytewise cut
  leaves exactly 2047. The rule reads `/proc/cmdline` as it is, which is
  the string both truncations act on.
- A cmdline that still carries its key-mode token is accepted at any
  length up to 2047. The guardian re-parses the full measured cmdline, so
  anything cut after the token (a duplicate, the guardian tokens) fails
  there.

**vali's numbers, in measured bytes (without the prefix):**

| Constant | Measured bytes |
|---|---|
| `MAX_MEASURED_CMDLINE_LEN` (never cut) | 2033 = 2047 - 14 |
| Token-less floor | 2008 = 2022 - 14 |

- vali must refuse measured cmdlines over **2033**. Today it refuses over
  2047, so 2034 to 2047 are cut in the guest.
- vali must refuse token-less (M0) cmdlines of **2008** bytes or more.
  The guest refuses them, so an M0 launch in that band no longer boots.
- The guardian's `LaunchRecipe` check uses 2033.

**What the rule cannot see.** It cannot see a key-mode token dropped
behind a long token that straddles the limit, or anything after a `\n`,
where the EFI stub stops. Neither yields a key the customer did not
approve. A guest that believes it is M0 never asks the guardian, so the VM
never enrolls, and the customer's first-boot enrollment check catches
that. It is the same as an M0 launch sold as M1.

## 3. M2: a miner that drops stamp confirms freezes the expectation

In M2 the volume stamp is the guardian's, not the KBS's. The guest writes
`E+1` into the encrypted upper and then sends the confirm to the guardian
through the miner's relay. A miner that drops every confirm freezes the
guardian's expectation at `E`, exactly as dropping the confirm to the KBS
does in M0/M1. `E` stays enforced as a floor, so the miner can roll the
upper back only to a state written since the last confirm that landed,
never further. The guardian bounds how long this can go on: each release
it grants without a matching confirm counts against its
unconfirmed-release limit, and once that limit is reached it stops
releasing `share_C` until a confirm lands.

**The confirm answer is signed (H1b).** The miner relays the guardian's
answer too, so an unsigned "confirmed" would let it report a confirm it
dropped. The answer is a `SignedGuardianStampAck`: Ed25519 by the
guardian identity key over `hippius-guardian-stamp-ack-v1\0 ‖ body`,
`body = {v, vm_id, target, token_hash}` with `token_hash =
sha256(token)`. The guest verifies it against the MEASURED `guardian_pk`
and requires `vm_id`, `target` and `token_hash` to echo its own confirm.
The token hash is what stops an ack recorded before a guardian re-init
or an authorised rollback (same `vm_id` and `target`) from answering a
confirm now, which holds only if the guardian mints the stamp token at
random for every release. A deterministic `HMAC(mac_key, vm_id ‖ target)`
token would recur with its target. The guardian must also answer a
re-presented token for the target it already holds with the same signed
ack (the CAS committed, the ack was lost), or the guest's retries fail
closed on a stamp that did advance. The mandatory first-boot confirm
succeeds only on a verified ack; anything else is a failed attempt (5,
then fail closed before the user-data is installed). Later boots still
only log success on a verified ack.
