"""Pure validation shared by every HTTP process."""
from dataclasses import dataclass
from .limits import RegistryLimits, InputLimits, SamplingPolicy

@dataclass(frozen=True)
class CaptureProfile:
    policy: SamplingPolicy
    inputs: InputLimits
    registry: RegistryLimits


def capture_profile(profile, *, deployment_epoch=None):
    """Missing configuration disables capture; malformed supplied data fails closed.

    The file is trusted workload configuration. The browser cannot choose a
    sampling policy or qualify its own input. No numeric allocation is inferred.
    """
    if not isinstance(profile, dict) or "visibility" not in profile:
        return None
    value = profile["visibility"]
    if (
        not isinstance(value, dict)
        or set(value)
        != {"version", "policy_epoch", "deployment_epoch", "qualification", "inputs", "registry"}
        or value["version"] != "appchi-visibility-capture-v1"
    ):
        raise ValueError("Explicit versioned visibility capture profile required")
    if deployment_epoch is not None and value["deployment_epoch"] != deployment_epoch:
        raise ValueError("Visibility policy belongs to another deployment epoch")
    try:
        return CaptureProfile(
            SamplingPolicy(
                epoch=value["policy_epoch"],
                qualification=value["qualification"],
                deployment_epoch=value["deployment_epoch"],
            ),
            InputLimits(**value["inputs"]),
            RegistryLimits(**value["registry"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Invalid visibility capture policy or allocations") from error
