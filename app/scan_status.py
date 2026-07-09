from dataclasses import dataclass, field


VALID_TOOL_STATES = {"completed", "failed", "skipped"}


@dataclass
class ToolStatusTracker:
    records: list[dict] = field(default_factory=list)

    def mark(
        self,
        name: str,
        status: str,
        *,
        detail: str | None = None,
        return_code: int | None = None,
    ) -> None:
        if status not in VALID_TOOL_STATES:
            raise ValueError(f"Unsupported scanner status: {status}")
        record = next((item for item in self.records if item["name"] == name), None)
        if record is None:
            record = {"name": name}
            self.records.append(record)
        record["status"] = status
        if detail:
            record["detail"] = detail
        elif "detail" in record:
            del record["detail"]
        if return_code is not None:
            record["return_code"] = return_code

    def failures(self) -> list[str]:
        return [item["name"] for item in self.records if item["status"] == "failed"]

    def states(self) -> dict[str, str]:
        return {item["name"]: item["status"] for item in self.records}

    def has(self, name: str) -> bool:
        return any(item["name"] == name for item in self.records)
