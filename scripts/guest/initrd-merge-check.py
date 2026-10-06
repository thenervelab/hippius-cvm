#!/usr/bin/env python3
"""`initrd-merge-check.py` — append a guest components release member to a
golden base's initrd and prove the result boots what the release says
(docs/design/guest-component-rollout.md, "One initrd per base").

    initrd = base_initrd ‖ zeros((-len(base_initrd)) mod 4) ‖ release_cpio

The kernel unpacks that buffer member by member into one rootfs, and its
unpacker is NOT an overlay: a later entry replaces an earlier one of the
same type, but a type change goes through `clean_path` (an `rmdir` that
fails on a non-empty directory, an `unlink` of a symlink), a directory
entry for a usrmerge parent (`lib`) would replace the `lib -> usr/lib`
symlink with an empty directory, and a regular file written over a base
file truncates that file's INODE, hard links included. So this tool does
not trust file lists: it unpacks the base initrd and then the release with
the rules of `init/initramfs.c` and checks the MERGED tree against the
release manifest (scripts/guest/build-guest-release.sh writes it):

    <path> file <mode> <sha256>         member entry: present, same bytes
    <path> dir <mode> -                 member entry: a NEW directory
    expect <sha256> <path>[|<path>...]  a base file the release relies on
    expect-link <resolves-to> <path>    a base symlink the release relies on
    needs <command>                     on the initramfs PATH

The unpack follows `unpack_to_rootfs`: zero bytes skipped; an uncompressed
member only where a '0' sits on a 4-byte boundary, and after its trailer
the next non-zero byte must be 4-byte aligned ("broken padding"); any
other byte starts ONE compressed member, decoded to its exact end (the
decompressor's consumed-byte count), whose content must end on a trailer
("junk at the end of compressed archive"); then the outer loop goes on.
Hard links (newc nlink >= 2, keyed on dev/ino, forgotten at each trailer)
share an inode.

Refused: an entry whose parent does not resolve to a directory in the base
(the kernel drops it silently), any type change against the base, a
directory entry over an existing path, a member file that lands over a
base file hard-linked elsewhere, a member file not landing with the
manifest's bytes and mode, an unmet `expect` / `expect-link` / `needs`, a
member that is not 4-byte aligned, a base initrd with no compressed member
or one that does not decode cleanly.

With --out it writes the appended initrd (only when every check passed).

Exit: 0 ok, 2 usage, 3 refused (a check failed).
"""

from __future__ import annotations

import argparse
import bz2
import hashlib
import lzma
import shutil
import struct
import subprocess
import sys
import zlib
from dataclasses import dataclass, field

S_IFMT = 0o170000
S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000

PATH_DIRS = ("bin", "sbin", "usr/bin", "usr/sbin")


class Refused(Exception):
    """A check failed: the appended initrd must not be used."""


@dataclass(eq=False)
class Inode:
    """A regular file's content, shared by its hard links."""

    sha256: str
    mode: int


@dataclass
class Node:
    kind: str  # "dir" | "file" | "symlink" | "other"
    mode: int
    target: str = ""
    inode: Inode | None = None


@dataclass
class Entry:
    name: str
    mode: int
    data: bytes
    nlink: int = 1
    key: tuple[int, int, int] = (0, 0, 0)  # (devmajor, devminor, ino)


TRAILER = "TRAILER!!!"


@dataclass
class Tree:
    nodes: dict[str, Node] = field(default_factory=lambda: {"": Node("dir", 0o755)})
    # The current archive's hard-link table (find_link); cleared at TRAILER.
    links: dict[tuple[int, int, int], str] = field(default_factory=dict)

    # ── path resolution (intermediate symlinks followed, like a path walk)
    def resolve_dir(self, path: str, depth: int = 0) -> str | None:
        """The canonical path of directory `path` (symlinks followed), or
        None when some component does not exist or is not a directory."""
        if depth > 40:
            return None
        cur = ""
        parts = [p for p in path.split("/") if p not in ("", ".")]
        for i, part in enumerate(parts):
            if part == "..":
                cur = cur.rsplit("/", 1)[0] if "/" in cur else ""
                continue
            cand = f"{cur}/{part}" if cur else part
            node = self.nodes.get(cand)
            if node is None:
                return None
            if node.kind == "symlink":
                tgt = node.target
                base = "" if tgt.startswith("/") else cur
                joined = f"{base}/{tgt}" if base else tgt
                rest = "/".join(parts[i + 1:])
                return self.resolve_dir(f"{joined}/{rest}" if rest else joined, depth + 1)
            if node.kind != "dir":
                return None
            cur = cand
        return cur

    def locate(self, path: str) -> str | None:
        """Canonical path of `path`'s FINAL component (not followed)."""
        path = path.strip("/")
        parent, _, name = path.rpartition("/")
        pdir = self.resolve_dir(parent)
        if pdir is None:
            return None
        return f"{pdir}/{name}" if pdir else name

    def resolve(self, path: str, depth: int = 0) -> str | None:
        """Canonical path with the final symlink followed too."""
        loc = self.locate(path)
        if loc is None or depth > 40:
            return None
        node = self.nodes.get(loc)
        if node is not None and node.kind == "symlink":
            tgt = node.target
            base = "" if tgt.startswith("/") else loc.rpartition("/")[0]
            return self.resolve(f"{base}/{tgt}" if base else tgt, depth + 1)
        return loc

    def children(self, path: str) -> list[str]:
        prefix = f"{path}/" if path else ""
        return [p for p in self.nodes if p.startswith(prefix) and p != path]

    def aliases(self, loc: str) -> list[str]:
        """Other paths sharing `loc`'s inode (hard links)."""
        node = self.nodes.get(loc)
        if node is None or node.inode is None:
            return []
        return [p for p, n in self.nodes.items() if p != loc and n.inode is node.inode]

    def _remove(self, loc: str) -> bool:
        """rmdir / unlink `loc`; False when a non-empty directory."""
        existing = self.nodes.get(loc)
        if existing is None:
            return True
        if existing.kind == "dir" and self.children(loc):
            return False
        del self.nodes[loc]
        return True

    def _clean_path(self, loc: str, fmt: int) -> bool:
        """clean_path(): an existing entry whose type differs from `fmt`
        (any entry, for fmt 0) goes. False when it could not."""
        existing = self.nodes.get(loc)
        if existing is None:
            return True
        kind_mode = {"dir": S_IFDIR, "file": S_IFREG, "symlink": S_IFLNK}.get(existing.kind, -1)
        if fmt != 0 and kind_mode == fmt:
            return True
        return self._remove(loc)

    # ── the kernel's unpack of one entry (init/initramfs.c do_name & co.)
    def apply(self, e: Entry) -> str:
        """Unpack one entry. Returns its canonical path, or "" when the
        kernel would not create it (or for the trailer)."""
        if e.name == TRAILER:
            self.links.clear()
            return ""
        loc = self.locate(e.name)
        if loc is None:
            return ""
        fmt = e.mode & S_IFMT
        perm = e.mode & 0o7777
        if fmt == S_IFLNK:
            # do_symlink(): clean_path(name, 0) — whatever is there goes.
            if not self._clean_path(loc, 0):
                return ""
            self.nodes[loc] = Node("symlink", 0o777, target=e.data.decode())
            return loc
        cleaned = self._clean_path(loc, fmt)
        if fmt == S_IFREG:
            sha = hashlib.sha256(e.data).hexdigest()
            if e.nlink >= 2:
                first = self.links.get(e.key)
                if first is not None:
                    # maybe_link(): clean_path(name, 0), then a hard link to
                    # the first name; the data then goes into that inode.
                    src = self.nodes.get(first)
                    if not self._clean_path(loc, 0) or src is None or src.inode is None:
                        return ""
                    if e.data:
                        src.inode.sha256 = sha
                    src.inode.mode = perm
                    self.nodes[loc] = Node("file", perm, inode=src.inode)
                    self._sync_modes(src.inode)
                    return loc
                self.links[e.key] = loc
            if not cleaned:
                return ""
            existing = self.nodes.get(loc)
            if existing is not None and existing.inode is not None:
                # Same type: opened O_TRUNC — the existing INODE is
                # rewritten, so every hard link to it changes too.
                existing.inode.sha256 = sha
                existing.inode.mode = perm
                self._sync_modes(existing.inode)
            else:
                self.nodes[loc] = Node("file", perm, inode=Inode(sha, perm))
            return loc
        if not cleaned:
            return ""
        if fmt == S_IFDIR:
            existing = self.nodes.get(loc)
            if existing is None:
                self.nodes[loc] = Node("dir", perm)
            else:
                existing.mode = perm  # chmod of the existing directory
        else:
            self.nodes[loc] = Node("other", perm)
        return loc

    def _sync_modes(self, inode: Inode) -> None:
        for n in self.nodes.values():
            if n.inode is inode:
                n.mode = inode.mode


def parse_cpio(buf: bytes, off: int) -> tuple[list[Entry], int]:
    """Parse one newc/crc archive at `off` up to and including its trailer
    (returned as an entry: it clears the hard-link table). Returns the
    entries and the offset just after the trailer."""
    entries: list[Entry] = []
    while True:
        if off % 4:
            raise Refused(f"cpio header at {off} not 4-byte aligned")
        hdr = buf[off:off + 110]
        if len(hdr) < 110 or hdr[:6] not in (b"070701", b"070702"):
            raise Refused(f"bad cpio header at {off}")
        f = [int(hdr[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
        ino, mode, nlink, filesize, devmaj, devmin, namesize = f[0], f[1], f[4], f[6], f[7], f[8], f[11]
        name = buf[off + 110:off + 110 + namesize - 1].decode()
        off = (off + 110 + namesize + 3) & ~3
        data = buf[off:off + filesize]
        if len(data) != filesize:
            raise Refused(f"truncated cpio entry {name!r}")
        off = (off + filesize + 3) & ~3
        if name == TRAILER:
            entries.append(Entry(TRAILER, 0, b""))
            return entries, off
        name = name.lstrip("/")
        if name.startswith("./"):
            name = name[2:]
        if name in ("", "."):
            continue
        entries.append(Entry(name, mode, data, nlink, (devmaj, devmin, ino)))


def _zstd_frame_len(blob: bytes) -> int:
    """Length of the zstd frame at the start of `blob` (RFC 8878 §3.1.1),
    read from its block headers without decoding it."""
    if blob[:4] != b"\x28\xb5\x2f\xfd" or len(blob) < 6:
        raise Refused("bad zstd frame")
    fhd = blob[4]
    fcs_flag, single, checksum, dict_flag = fhd >> 6, (fhd >> 5) & 1, (fhd >> 2) & 1, fhd & 3
    off = 5 + (0 if single else 1) + (0, 1, 2, 4)[dict_flag]
    off += (1 if single else 0, 2, 4, 8)[fcs_flag]
    while True:
        if off + 3 > len(blob):
            raise Refused("truncated zstd frame")
        (hdr,) = struct.unpack_from("<I", blob[off:off + 3] + b"\x00")
        last, btype, bsize = hdr & 1, (hdr >> 1) & 3, hdr >> 3
        if btype == 3:
            raise Refused("reserved zstd block type")
        off += 3 + (1 if btype == 1 else bsize)
        if last:
            break
    off += 4 if checksum else 0
    if off > len(blob):
        raise Refused("truncated zstd frame")
    return off


def _inflate(blob: bytes) -> tuple[bytes, int]:
    """Decode ONE compressed member at the start of `blob`, as the kernel's
    decompressor does: (content, bytes consumed)."""
    try:
        if blob.startswith(b"\x1f\x8b"):
            d = zlib.decompressobj(wbits=31)
            out = d.decompress(blob)
            if not d.eof:
                raise Refused("truncated gzip member")
            return out, len(blob) - len(d.unused_data)
        for magic, fmt in ((b"\xfd7zXZ\x00", lzma.FORMAT_XZ), (b"\x5d\x00\x00", lzma.FORMAT_ALONE)):
            if blob.startswith(magic):
                x = lzma.LZMADecompressor(format=fmt)
                out = x.decompress(blob)
                if not x.eof:
                    raise Refused("truncated xz/lzma member")
                return out, len(blob) - len(x.unused_data)
        if blob.startswith(b"BZh"):
            b = bz2.BZ2Decompressor()
            out = b.decompress(blob)
            if not b.eof:
                raise Refused("truncated bzip2 member")
            return out, len(blob) - len(b.unused_data)
    except (zlib.error, lzma.LZMAError, OSError) as exc:
        raise Refused(f"the base initrd does not decode: {exc}") from exc
    if blob.startswith(b"\x28\xb5\x2f\xfd"):
        n = _zstd_frame_len(blob)
        if shutil.which("zstd") is None:
            raise Refused("need zstd to read this base initrd")
        proc = subprocess.run(["zstd", "-dcq"], input=blob[:n], capture_output=True, check=False)
        if proc.returncode != 0:
            raise Refused(f"zstd could not decode the base initrd: {proc.stderr[:200]!r}")
        return proc.stdout, n
    raise Refused(f"unsupported or unknown compressed member (magic {blob[:6].hex()})")


def _parse_stream(data: bytes) -> list[Entry]:
    """The archives inside one decompressed member (flush_buffer): cpio,
    zero padding, cpio…, ending on a trailer."""
    entries: list[Entry] = []
    off = 0
    while off < len(data):
        if data[off] == 0:
            off += 1
            continue
        if data[off:off + 1] != b"0":
            raise Refused("junk within compressed archive")
        got, off = parse_cpio(data, off)
        entries += got
    return entries


def unpack_initrd(buf: bytes) -> tuple[list[Entry], int]:
    """Every entry of an initrd image in unpack order (unpack_to_rootfs),
    and how many compressed members it had."""
    entries: list[Entry] = []
    off = 0
    compressed = 0
    while off < len(buf):
        if buf[off:off + 1] == b"0" and off % 4 == 0:
            got, off = parse_cpio(buf, off)
            entries += got
            # do_reset(): zeros are eaten; what follows must be aligned.
            while off < len(buf) and buf[off] == 0:
                off += 1
            if off < len(buf) and off % 4:
                raise Refused(f"broken padding after an uncompressed member (offset {off})")
            continue
        if buf[off] == 0:
            off += 1
            continue
        content, used = _inflate(buf[off:])
        entries += _parse_stream(content)
        off += used
        compressed += 1
    return entries, compressed


@dataclass
class Manifest:
    members: list[tuple[str, str, int, str]] = field(default_factory=list)
    expects: list[tuple[str, list[str]]] = field(default_factory=list)
    links: list[tuple[str, str]] = field(default_factory=list)
    needs: list[str] = field(default_factory=list)


def parse_manifest(text: str) -> Manifest:
    m = Manifest()
    for n, line in enumerate(text.splitlines(), 1):
        f = line.split()
        if not f:
            continue
        if f[0] == "expect" and len(f) == 3:
            m.expects.append((f[1], f[2].split("|")))
        elif f[0] == "expect-link" and len(f) == 3:
            m.links.append((f[1], f[2]))
        elif f[0] == "needs" and len(f) == 2:
            m.needs.append(f[1])
        elif len(f) == 4 and f[1] in ("file", "dir"):
            m.members.append((f[0], f[1], int(f[2], 8), f[3]))
        else:
            raise SystemExit(f"manifest line {n}: cannot parse: {line!r}")
    if not m.members:
        raise SystemExit("manifest lists no member entry")
    return m


def check(base: bytes, release: bytes, manifest: Manifest) -> list[str]:
    """Merge and check. Returns the list of refusals (empty = ok)."""
    errs: list[str] = []
    if len(release) % 4:
        errs.append("the release member's length is not a multiple of 4")
    tree = Tree()
    base_entries, compressed = unpack_initrd(base)
    if not compressed:
        raise Refused("the base initrd has no compressed member (not a distro initrd?)")
    for e in base_entries:
        tree.apply(e)
    # Releases are appended to the base's OWN initrd, never to an earlier
    # release build: whatever an older release carried would stay in the
    # tree (a file a newer release no longer ships, an old busybox…).
    if tree.resolve("lib/hippius/guest/release") in tree.nodes:
        errs.append("the base initrd already carries a guest release — releases are appended "
                    "to the base's own initrd, never chained")
    base_kinds = {p: n.kind for p, n in tree.nodes.items()}
    base_aliases = {p: tree.aliases(p) for p, n in tree.nodes.items() if n.inode is not None}

    rel_entries, end = parse_cpio(release, 0)
    if release[end:].strip(b"\x00"):
        errs.append("trailing bytes after the release member's trailer")
    listed = {(p, k) for p, k, _, _ in manifest.members}
    for e in rel_entries:
        if e.name == TRAILER:
            tree.apply(e)
            continue
        kind = {S_IFDIR: "dir", S_IFREG: "file", S_IFLNK: "symlink"}.get(e.mode & S_IFMT, "other")
        if (e.name, kind) not in listed:
            errs.append(f"{e.name}: in the member but not in the manifest")
        if kind == "file" and e.nlink != 1:
            errs.append(f"{e.name}: a hard link in the release member")
        loc = tree.locate(e.name)
        if loc is None:
            errs.append(f"{e.name}: its parent is not a directory in the base (the kernel drops it)")
            continue
        before = base_kinds.get(loc)
        if kind == "dir" and before is not None:
            errs.append(f"{e.name}: a directory entry over an existing {before} ({loc})")
        elif before is not None and before != kind:
            errs.append(f"{e.name}: replaces a {before} with a {kind} ({loc})")
        if base_aliases.get(loc):
            errs.append(f"{e.name}: overwrites a base file hard-linked as "
                        f"{', '.join(base_aliases[loc])} (it would change too)")
        if not tree.apply(e):
            errs.append(f"{e.name}: the kernel would not create it")

    for path, kind, mode, sha in manifest.members:
        loc = tree.locate(path)
        node = tree.nodes.get(loc) if loc is not None else None
        if node is None or node.kind != kind:
            errs.append(f"{path}: not a {kind} in the merged tree")
            continue
        if node.mode != mode:
            errs.append(f"{path}: mode {node.mode:04o}, want {mode:04o}")
        if kind == "file" and (node.inode is None or node.inode.sha256 != sha):
            errs.append(f"{path}: content differs from the manifest")

    for sha, paths in manifest.expects:
        ok = False
        for p in paths:
            loc = tree.resolve(p)
            node = tree.nodes.get(loc) if loc is not None else None
            if node is not None and node.inode is not None and node.inode.sha256 == sha:
                ok = True
                break
        if not ok:
            errs.append(f"expected base file not found with its content: {'|'.join(paths)}")

    for target, path in manifest.links:
        loc = tree.locate(path)
        node = tree.nodes.get(loc) if loc is not None else None
        want = tree.resolve(target)
        if node is None or node.kind != "symlink" or tree.resolve(path) != want or want not in tree.nodes:
            errs.append(f"expected base link {path} -> {target} is missing or points elsewhere")

    for cmd in manifest.needs:
        found = False
        for d in PATH_DIRS:
            loc = tree.resolve(f"{d}/{cmd}")
            node = tree.nodes.get(loc) if loc is not None else None
            if node is not None and node.kind == "file" and node.mode & 0o111:
                found = True
                break
        if not found:
            errs.append(f"command {cmd} is not on the initramfs PATH (as an executable file)")
    return errs


# The golden boot entry point each family's initrd carries (the hook /
# dracut module installs it), which tells the two apart.
FAMILY_MARKERS = {
    "initramfs-tools": "scripts/hippius-golden",
    "dracut": "sbin/hippius-golden-mount",
}


def detect_family(base: bytes) -> str:
    """The initramfs family of a golden base initrd, from its merged tree."""
    tree = Tree()
    entries, compressed = unpack_initrd(base)
    if not compressed:
        raise Refused("the base initrd has no compressed member (not a distro initrd?)")
    for e in entries:
        tree.apply(e)
    found = []
    for family, marker in FAMILY_MARKERS.items():
        loc = tree.resolve(marker)
        node = tree.nodes.get(loc) if loc is not None else None
        if node is not None and node.kind == "file":
            found.append(family)
    if len(found) != 1:
        raise Refused(f"cannot tell the initramfs family (golden entry points found: {found or 'none'})")
    return found[0]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", required=True, help="the base initrd (as the VM boots it today)")
    ap.add_argument("--detect-family", action="store_true",
                    help="only print the base's initramfs family (initramfs-tools | dracut)")
    ap.add_argument("--release", help="release-<family>.cpio")
    ap.add_argument("--manifest", help="release-<family>.manifest")
    ap.add_argument("--out", help="write the appended initrd here when every check passed")
    ap.add_argument("--need", action="append", default=[], metavar="COMMAND",
                    help="one more command the initramfs PATH must carry (repeatable)")
    a = ap.parse_args()
    with open(a.base, "rb") as f:
        base = f.read()
    if a.detect_family:
        try:
            print(detect_family(base))
        except Refused as exc:
            print(f"initrd-merge-check: REFUSED: {exc}", file=sys.stderr)
            return 3
        return 0
    if not (a.release and a.manifest):
        ap.error("--release and --manifest are required (unless --detect-family)")
    with open(a.release, "rb") as f:
        release = f.read()
    with open(a.manifest, encoding="utf-8") as f:
        manifest = parse_manifest(f.read())
    manifest.needs += a.need
    merged = base + b"\x00" * ((-len(base)) % 4) + release
    try:
        errs = check(base, release, manifest)
        if not errs:
            # The appended image itself unpacks cleanly, release included.
            unpack_initrd(merged)
    except Refused as exc:
        errs = [str(exc)]
    if errs:
        for e in errs:
            print(f"initrd-merge-check: REFUSED: {e}", file=sys.stderr)
        return 3
    if a.out:
        with open(a.out, "wb") as f:
            f.write(merged)
    print(f"initrd-merge-check: OK initrd_sha256={hashlib.sha256(merged).hexdigest()} "
          f"base={len(base)} pad={(-len(base)) % 4} release={len(release)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
