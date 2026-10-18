"""Logging filters installed on every vali handler (`settings.LOGGING`).

`SerialRedactionFilter`: hardware serials and `/dev/disk/by-id/` names
are the node owner's (§18.10.3) — served by the owner-scoped operator
reads, never written to a log line. Code never logs them on purpose; this
is the net under a mistake (an exception message quoting a body, a debug
line): a `serial` key's value and any by-id name are replaced before the
record is emitted."""

from __future__ import annotations

import logging
import re

#: A by-id name of a physical device (the host-inventory crate's
#: `DISK_ID_PREFIXES`), long enough to carry an identifier and holding a
#: digit — so a tool name (`nvme-cli`) passes.
_BY_ID = re.compile(
    r"\b(?:wwn|nvme|ata|scsi|usb|virtio|mmc|ieee1394)-"
    r"(?=[A-Za-z0-9._:-]{0,95}\d)[A-Za-z0-9._:-]{6,96}"
)
#: `serial: x`, `"serial": "x"`, `serial=x`, `product_serial='x'`.
_SERIAL = re.compile(r"""(?i)(\b\w*serial["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;}\]]+)""")


def redact(text: str) -> str:
    text = _SERIAL.sub(r'\1"<redacted>"', text)
    return _BY_ID.sub("<by-id>", text)


class SerialRedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 — a malformed call is the handler's to report.
            return True
        redacted = redact(message)
        if redacted != message:
            record.msg = redacted
            record.args = None
        # A traceback quoting a body: format it once here, redacted; the
        # formatter reuses the cached `exc_text`.
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        if record.stack_info:
            record.stack_info = redact(record.stack_info)
        return True
