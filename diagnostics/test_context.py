
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import StrEnum
from uuid import uuid4
import json


class TestEnvironment(StrEnum):
    SERVER = "server"
    DEVICE = "device"


class ConnectionType(StrEnum):
    MOBILE_DATA = "mobile_data"
    WIFI = "wifi"
    ETHERNET = "ethernet"
    UNKNOWN = "unknown"


class DataBundleStatus(StrEnum):
    ACTIVE = "active"
    NONE = "none"
    UNKNOWN = "unknown"


class InformationOrigin(StrEnum):
    USER_DECLARED = "user_declared"
    SYSTEM_DETECTED = "system_detected"
    SOURCE_VERIFIED = "source_verified"
    UNKNOWN = "unknown"


@dataclass
class TestContext:
    environment: TestEnvironment
    connection_type: ConnectionType

    country_code: str | None = None
    operator_code: str | None = None
    operator_name: str | None = None
    data_activity: str | None = None
    connection_confidence: str | None = None
    bundle_status: DataBundleStatus = DataBundleStatus.UNKNOWN

    device_type: str | None = None
    network_generation: str | None = None

    measurement_location: str | None = None

    information_sources: dict[str, InformationOrigin] = field(
        default_factory=dict
    )

    context_id: str = field(
        default_factory=lambda: str(uuid4())
    )

    created_at: str = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )

    def __post_init__(self):
        if self.country_code:
            self.country_code = self.country_code.strip().upper()

        if self.operator_code:
            self.operator_code = self.operator_code.strip().upper()

        if self.measurement_location:
            self.measurement_location = (
                self.measurement_location.strip()
            )

        allowed_fields = {
            "country_code",
            "operator_code",
            "operator_name",
            "data_activity",
            "connection_confidence",
            "connection_type",
            "bundle_status",
            "device_type",
            "network_generation",
            "measurement_location",
        }

        for key, origin in self.information_sources.items():
            if key not in allowed_fields:
                raise ValueError(
                    f"Champ de provenance inconnu : {key}"
                )

            if not isinstance(origin, InformationOrigin):
                raise TypeError(
                    f"Origine invalide pour le champ : {key}"
                )

    def to_dict(self):
        data = asdict(self)

        data["environment"] = self.environment.value
        data["connection_type"] = self.connection_type.value
        data["bundle_status"] = self.bundle_status.value

        data["information_sources"] = {
            key: origin.value
            for key, origin in self.information_sources.items()
        }

        return data

    def to_json(self):
        return json.dumps(
            self.to_dict(),
            indent=4,
            ensure_ascii=False
        )
