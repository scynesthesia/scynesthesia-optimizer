from __future__ import annotations

from pathlib import Path
from typing import List, Optional


class NVRAMProject:
    """Represent an editable NVRAM project file."""

    def __init__(self, file_path: Path | str, encoding: str = "utf-8") -> None:
        self.path = Path(file_path)
        self.encoding = encoding
        self.original_crc: Optional[str] = None
        self.blocks: List[str] = []
        self.raw_content: str = ""
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            raise FileNotFoundError(f"File not found: {self.path}")

        self.raw_content = self.path.read_text(encoding=self.encoding)
        lines = self.raw_content.splitlines()
        self.original_crc = self._extract_crc_from_header(lines)
        content_without_header = (
            "\n".join(lines[1:]) if self.has_hii_crc_header(lines) else self.raw_content
        )
        self.blocks = [
            block.strip() for block in content_without_header.split("\n\n") if block.strip()
        ]

    def has_hii_crc_header(self, lines: Optional[List[str]] = None) -> bool:
        lines = lines if lines is not None else self.raw_content.splitlines()
        if not lines:
            return False
        first_line = lines[0].strip()
        return first_line.lower().startswith("# hii crc32:")

    def _extract_crc_from_header(self, lines: List[str]) -> Optional[str]:
        if not self.has_hii_crc_header(lines):
            return None
        _, _, value = lines[0].partition(":")
        return value.strip() if value else None

    def recalculate_crc(self, new_content: str) -> Optional[str]:
        # TODO: Implementar algoritmo HIICrc32
        return self.original_crc


def has_hii_crc_header(file_path: Path | str) -> bool:
    project = NVRAMProject(file_path)
    return project.has_hii_crc_header()


__all__ = ["NVRAMProject", "has_hii_crc_header"]
