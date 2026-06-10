"""Log ingestion: turn raw log files into a stream of normalized Events."""

from bastion.ingest.base import LogSource, select_source
from bastion.ingest.evtx import EvtxSource
from bastion.ingest.linux import LinuxLogSource

__all__ = ["EvtxSource", "LinuxLogSource", "LogSource", "select_source"]
