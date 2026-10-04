"""Pluggable file validators for Help Peer."""
import json
from typing import Protocol


class ValidationError(Exception):
    pass


class FileValidator(Protocol):
    def file_extensions(self) -> list[str]: ...
    def validate_first_segment(self, data: bytes) -> None: ...


class SafetensorsValidator:
    """Validates safetensors files by parsing the JSON header."""

    def file_extensions(self) -> list[str]:
        return ["safetensors"]

    def validate_first_segment(self, data: bytes) -> None:
        if len(data) < 8:
            raise ValidationError("file too small to be a valid safetensors file")

        header_len = int.from_bytes(data[:8], "little")

        if header_len > 100_000_000:
            raise ValidationError(f"safetensors header length {header_len} is unreasonably large")

        if len(data) < 8 + header_len:
            raise ValidationError("safetensors header extends beyond first segment")

        header_json = data[8:8 + header_len]
        try:
            parsed = json.loads(header_json)
        except json.JSONDecodeError as e:
            raise ValidationError(f"safetensors header is not valid JSON: {e}")

        if not isinstance(parsed, dict):
            raise ValidationError("safetensors header is not a JSON object")

        if len(parsed) == 0:
            raise ValidationError("safetensors header is empty")


class GenericValidator:
    """Passthrough validator that accepts all data."""

    def file_extensions(self) -> list[str]:
        return []

    def validate_first_segment(self, data: bytes) -> None:
        pass


class ValidatorRegistry:
    def __init__(self):
        self.validators: list[FileValidator] = [SafetensorsValidator()]
        self.fallback: FileValidator = GenericValidator()

    def validator_for(self, path: str) -> FileValidator:
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        for v in self.validators:
            if ext in v.file_extensions():
                return v
        return self.fallback
