from dataclasses import dataclass


@dataclass(frozen=True)
class RegistryLimits:
    """All allocations supplied explicitly; no telemetry retention default."""

    lease_seconds: int
    max_active_session_views: int  # per session and tenant
    max_active_tenant_views: int
    max_tenant_controls: int
    max_descriptor_bytes: int
    max_request_bytes: int

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in vars(self).values()):
            raise ValueError("Positive integer registry allocations required")
        if self.max_request_bytes > 65536 or self.max_descriptor_bytes > self.max_request_bytes:
            raise ValueError("Request allocation cannot exceed 64 KiB")
        if self.max_active_session_views > self.max_active_tenant_views:
            raise ValueError("Session allocation exceeds tenant allocation")
        if max(self.max_tenant_controls, self.max_active_tenant_views) >= 2**63 - 1:
            raise ValueError("Allocation exceeds PostgreSQL bigint range")
        if self.lease_seconds > 86400:
            raise ValueError("A view contact lease cannot exceed one day")


@dataclass(frozen=True)
class InputLimits:
    max_tenant_inputs: int
    max_tenant_candidates: int
    max_tenant_applications: int
    max_tenant_application_bytes: int
    max_application_bytes: int
    max_views_per_turn: int

    def __post_init__(self):
        if any(
            type(value) is not int or not 0 < value < 2**63 - 1 for value in vars(self).values()
        ):
            raise ValueError("Explicit positive bounded visibility allocations required")
        if self.max_application_bytes > self.max_tenant_application_bytes:
            raise ValueError("Application allocation exceeds tenant allocation")
        if self.max_views_per_turn > 200:
            raise ValueError("One expansion transaction may inspect at most 200 views")


@dataclass(frozen=True)
class SamplingPolicy:
    epoch: str
    qualification: bool
    deployment_epoch: str

    def __post_init__(self):
        if (
            not isinstance(self.epoch, str)
            or not 1 <= len(self.epoch.encode()) <= 256
            or type(self.qualification) is not bool
        ):
            raise ValueError("Immutable server sampling policy required")
        if (
            not isinstance(self.deployment_epoch, str)
            or not 1 <= len(self.deployment_epoch.encode()) <= 256
        ):
            raise ValueError("Explicit deployment epoch required")
