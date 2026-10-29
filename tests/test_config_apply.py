"""Tests for app/config_apply.py — the key-routing layer that splits a stored
template / raw config between PATCH /import/ and the dedicated per-section
endpoints.

Regression: templates built by save_as_template merge the output of
get_security_config(), which flattens four separate v4 endpoints into one dict.
Apply then fed that dict to PATCH /import/, which only accepts the components
GET /export/ emits. The API rejects on the first unrecognised key, so a
template containing protection_mode failed with

    400 ['Component named "protection_mode" not found.']

and wrote nothing at all. Four of five stored templates were affected.
"""

import pytest

from app.config_apply import (
    SECTION_ROUTES,
    apply_config,
    apply_error_summary,
    apply_succeeded,
    capture_before,
    split_config,
)
from app.waas_client import WaasApiError


class StubClient:
    """Records calls; can be told to fail specific methods."""

    def __init__(self, fail=None, export=None, sections=None):
        self.calls = []
        self.fail = fail or set()
        self._export = export if export is not None else {'request_limits': {'enabled': True}}
        self._sections = sections or {}

    def _maybe_fail(self, name):
        if name in self.fail:
            raise WaasApiError(f'{name} exploded')

    def import_application(self, app_id, payload, include_servers=False, include_endpoints=False):
        self.calls.append(('import_application', app_id, payload, include_servers, include_endpoints))
        self._maybe_fail('import_application')

    def update_security_config(self, app_id, payload):
        self.calls.append(('update_security_config', app_id, payload))
        self._maybe_fail('update_security_config')

    def update_clickjacking_protection(self, app_id, payload):
        self.calls.append(('update_clickjacking_protection', app_id, payload))
        self._maybe_fail('update_clickjacking_protection')

    def update_data_theft_protection(self, app_id, payload):
        self.calls.append(('update_data_theft_protection', app_id, payload))
        self._maybe_fail('update_data_theft_protection')

    # --- reads, for capture_before ---
    def get_application(self, app_id):
        self.calls.append(('get_application', app_id))
        self._maybe_fail('get_application')
        return dict(self._export)

    def get_basic_security(self, app_id):
        self.calls.append(('get_basic_security', app_id))
        self._maybe_fail('get_basic_security')
        return self._sections.get('basic_security', {'protection_mode': 'Passive'})

    def get_clickjacking_protection(self, app_id):
        self.calls.append(('get_clickjacking_protection', app_id))
        self._maybe_fail('get_clickjacking_protection')
        return self._sections.get('clickjacking_protection', {'enabled': False})

    def get_data_theft_protection(self, app_id):
        self.calls.append(('get_data_theft_protection', app_id))
        self._maybe_fail('get_data_theft_protection')
        return self._sections.get('data_theft_protection', {'enabled': False})


def method_names(stub):
    return [c[0] for c in stub.calls]


# The template that actually failed in production (template 6).
REAL_TEMPLATE = {
    'protection_mode': 'Active',
    'request_limits': {'enabled': True, 'max_request_length': 32768},
    'clickjacking_protection': {'enabled': True, 'render_options': 'Same Origin', 'allowed_origin': ''},
    'data_theft_protection': {'elements': [], 'custom_identity_theft_types': [], 'enabled': True},
}


class TestSplitConfig:
    def test_section_keys_are_separated_from_import_payload(self):
        sections, import_payload = split_config(REAL_TEMPLATE)
        assert {key for key, _, _ in sections} == set(SECTION_ROUTES)
        # Only the genuinely importable key is left for /import/.
        assert import_payload == {'request_limits': REAL_TEMPLATE['request_limits']}

    def test_protection_mode_is_wrapped_for_basic_security(self):
        sections, _ = split_config({'protection_mode': 'Active'})
        (key, _label, payload), = sections
        assert key == 'protection_mode'
        # PATCH /basic_security/ takes the key, not the bare value.
        assert payload == {'protection_mode': 'Active'}

    def test_other_sections_are_sent_as_whole_body(self):
        cj = {'enabled': True, 'render_options': 'Same Origin'}
        sections, _ = split_config({'clickjacking_protection': cj})
        (_key, _label, payload), = sections
        assert payload == cj

    def test_unknown_keys_pass_through_to_import(self):
        sections, import_payload = split_config({'servers': [], 'website_profile': {'mode': 'Active'}})
        assert sections == []
        assert import_payload == {'servers': [], 'website_profile': {'mode': 'Active'}}

    def test_request_limits_is_not_a_section(self):
        # It appears in the export document with the same shape, so it must
        # keep riding along in the import payload.
        assert 'request_limits' not in SECTION_ROUTES

    def test_empty_config(self):
        assert split_config({}) == ([], {})
        assert split_config(None) == ([], {})


class TestApplyConfig:
    def test_the_production_failure_now_routes_correctly(self):
        stub = StubClient()
        results = apply_config(stub, 'My New App', REAL_TEMPLATE)

        assert apply_succeeded(results)
        assert set(method_names(stub)) == {
            'update_security_config',
            'update_clickjacking_protection',
            'update_data_theft_protection',
            'import_application',
        }
        # The import call carries only importable keys — this is the assertion
        # that pins the original 400.
        import_call = next(c for c in stub.calls if c[0] == 'import_application')
        assert set(import_call[2]) == {'request_limits'}

    def test_import_is_skipped_when_nothing_importable_remains(self):
        stub = StubClient()
        apply_config(stub, 'app', {'protection_mode': 'Active'})
        assert method_names(stub) == ['update_security_config']

    def test_import_only_config_makes_one_call(self):
        stub = StubClient()
        results = apply_config(stub, 'app', {'request_limits': {'enabled': True}})
        assert method_names(stub) == ['import_application']
        assert apply_succeeded(results)

    def test_include_flags_reach_import_application(self):
        stub = StubClient()
        apply_config(stub, 'app', {'servers': []}, include_servers=True, include_endpoints=True)
        _, _, _, include_servers, include_endpoints = stub.calls[0]
        assert include_servers is True
        assert include_endpoints is True

    def test_include_flags_are_not_passed_to_section_endpoints(self):
        stub = StubClient()
        apply_config(stub, 'app', {'protection_mode': 'Active'}, include_servers=True)
        # update_security_config records (name, app_id, payload) only.
        assert len(stub.calls[0]) == 3

    def test_empty_config_attempts_nothing(self):
        stub = StubClient()
        results = apply_config(stub, 'app', {})
        assert stub.calls == []
        assert results == []
        # No parts ran, so this is not a success.
        assert not apply_succeeded(results)


class TestPartialFailure:
    def test_one_failing_section_does_not_block_the_others(self):
        stub = StubClient(fail={'update_clickjacking_protection'})
        results = apply_config(stub, 'app', REAL_TEMPLATE)

        assert not apply_succeeded(results)
        # Everything was still attempted.
        assert len(results) == 4
        assert sum(1 for r in results if r['success']) == 3
        assert 'import_application' in method_names(stub)

    def test_failing_import_does_not_block_sections(self):
        stub = StubClient(fail={'import_application'})
        results = apply_config(stub, 'app', REAL_TEMPLATE)
        assert sum(1 for r in results if r['success']) == 3
        failed = [r for r in results if not r['success']]
        assert len(failed) == 1
        assert failed[0]['part'] == 'Application Config'

    def test_error_summary_names_the_failing_parts(self):
        stub = StubClient(fail={'update_security_config'})
        results = apply_config(stub, 'app', REAL_TEMPLATE)
        summary = apply_error_summary(results)
        assert 'Basic Security' in summary
        assert 'exploded' in summary

    def test_error_summary_is_none_when_all_succeed(self):
        stub = StubClient()
        assert apply_error_summary(apply_config(stub, 'app', REAL_TEMPLATE)) is None

    def test_api_errors_are_not_raised(self):
        stub = StubClient(fail={'update_security_config', 'import_application'})
        # Must not propagate — callers inspect results instead.
        results = apply_config(stub, 'app', REAL_TEMPLATE)
        assert not apply_succeeded(results)


class TestCaptureBefore:
    def test_section_state_is_merged_into_the_export(self):
        stub = StubClient(sections={'basic_security': {'protection_mode': 'Passive'}})
        before = capture_before(stub, 'app', REAL_TEMPLATE)

        # Without this, a revert could not restore protection_mode: the export
        # document simply does not contain it.
        assert before['protection_mode'] == 'Passive'
        assert 'clickjacking_protection' in before
        assert 'data_theft_protection' in before
        assert before['request_limits'] == {'enabled': True}

    def test_only_sections_the_config_touches_are_read(self):
        stub = StubClient()
        capture_before(stub, 'app', {'protection_mode': 'Active'})
        assert method_names(stub) == ['get_application', 'get_basic_security']

    def test_import_only_config_reads_nothing_extra(self):
        stub = StubClient()
        capture_before(stub, 'app', {'request_limits': {}})
        assert method_names(stub) == ['get_application']

    def test_unreadable_section_is_skipped_not_fatal(self):
        stub = StubClient(fail={'get_clickjacking_protection'})
        before = capture_before(stub, 'app', REAL_TEMPLATE)
        assert 'clickjacking_protection' not in before
        # The rest still captured.
        assert before['protection_mode'] == 'Passive'

    def test_export_failure_propagates(self):
        stub = StubClient(fail={'get_application'})
        with pytest.raises(WaasApiError):
            capture_before(stub, 'app', REAL_TEMPLATE)

    def test_captured_payload_round_trips_through_apply(self):
        """What capture_before records must be replayable by apply_config —
        this is what makes rollback of a template apply work."""
        stub = StubClient(sections={'basic_security': {'protection_mode': 'Passive'}})
        before = capture_before(stub, 'app', REAL_TEMPLATE)

        replay = StubClient()
        results = apply_config(replay, 'app', before, include_servers=True, include_endpoints=True)
        assert apply_succeeded(results)
        import_call = next(c for c in replay.calls if c[0] == 'import_application')
        # protection_mode must not end up back in the import payload.
        assert 'protection_mode' not in import_call[2]
        sec_call = next(c for c in replay.calls if c[0] == 'update_security_config')
        assert sec_call[2] == {'protection_mode': 'Passive'}
