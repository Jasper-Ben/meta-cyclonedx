"""Public configuration of the TR-03183-2 alignment profile.

The alignment profile and its alignment enforcement are selected through
the public BitBake variables CYCLONEDX_PROFILE and
CYCLONEDX_PROFILE_ENFORCEMENT; the renderer seam validates them through
config_errors, exactly like the CycloneDX version and image type.
"""

import meta_cyclonedx

PROFILE = "tr03183-2.1"


def test_supported_profile_and_enforcement_validate():
    assert meta_cyclonedx.config_errors("1.7", "firmware", profile=PROFILE, enforcement="report") is None
    assert meta_cyclonedx.config_errors("1.6", "firmware", profile=PROFILE, enforcement="strict") is None


def test_unsupported_profile_name_names_supported_profiles():
    error = meta_cyclonedx.config_errors("1.7", "firmware", profile="tr03183-9.9", enforcement="report")
    assert "CYCLONEDX_PROFILE" in error
    assert "tr03183-9.9" in error
    assert PROFILE in error


def test_unsupported_enforcement_value_is_rejected():
    error = meta_cyclonedx.config_errors("1.7", "firmware", profile=PROFILE, enforcement="conform")
    assert "CYCLONEDX_PROFILE_ENFORCEMENT" in error
    assert "report" in error
    assert "strict" in error


def test_profile_rejects_cyclonedx_below_16():
    error = meta_cyclonedx.config_errors("1.4", "firmware", profile=PROFILE, enforcement="report")
    assert "tr03183-2.1" in error
    assert "1.4" in error
    assert "1.6" in error


def test_enforcement_without_profile_is_rejected():
    error = meta_cyclonedx.config_errors("1.7", "firmware", profile="", enforcement="strict")
    assert "CYCLONEDX_PROFILE_ENFORCEMENT" in error
    assert "CYCLONEDX_PROFILE" in error
