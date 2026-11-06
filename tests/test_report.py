"""Report building and argument building are the non-trivial logic here, so they are what gets tested."""

from pydantic_ai_agent_network_access_probe import build_report, probe_args
from pydantic_ai_agent_network_access_probe._toolset import MAX_FINDINGS

SRC = 'C:/tmp/tool'
ATTESTATION = {
    'production_readiness_score': 45,
    'network_calls': [{'host': 'api.example.com', 'port': 443, 'protocol': 'tcp'}],
    'languages_detected': ['python'],
}


def finding(severity, title='t', file=f'{SRC}/tool.py', **extra):
    return {'severity': severity, 'title': title, 'file': file, **extra}


def test_worst_first_with_counts_and_allow_list():
    r = build_report(
        {'source': SRC, 'findings': [finding('info'), finding('critical'), finding('warning'), finding('critical')]},
        ATTESTATION,
    )
    assert [f.severity for f in r.findings] == ['critical', 'critical', 'warning', 'info']
    assert r.by_severity == {'info': 1, 'critical': 2, 'warning': 1}
    assert r.readiness_score == 45
    assert r.allow_list == ['api.example.com:443']
    assert r.languages == ['python']
    assert r.sandbox == 'off (static only)'


def test_paths_are_relative_to_the_scanned_directory():
    r = build_report(
        {'source': SRC + '/', 'findings': [finding('warning'), finding('warning', file='C:\\tmp\\tool\\sub\\x.py'),
                                          finding('info', file='')]},
        ATTESTATION,
    )
    assert [f.file for f in r.findings] == ['tool.py', 'sub/x.py', '']


def test_evidence_is_capped_and_clipped():
    ev = [{'source': 'static_analysis', 'label': 'No timeout', 'detail': 'x' * 400}] * 5
    r = build_report({'source': SRC, 'findings': [finding('critical', evidence=ev, fix_hint='  add timeout=10 \n')]},
                     ATTESTATION)
    f = r.findings[0]
    assert len(f.evidence) == 3
    assert f.evidence[0].startswith('[static_analysis] No timeout: ')
    assert len(f.evidence[0]) == len('[static_analysis] ') + 300
    assert f.fix_hint == 'add timeout=10'


def test_findings_are_truncated_but_counted():
    r = build_report({'source': SRC, 'findings': [finding('info')] * (MAX_FINDINGS + 7)}, ATTESTATION)
    assert len(r.findings) == MAX_FINDINGS
    assert r.findings_total == MAX_FINDINGS + 7
    assert r.findings_truncated == 7


def test_sandbox_state_and_notes():
    profile_ran = {'tools': [{'path': 'tool.py', 'harness_id': 'h1'}]}
    stderr = '\x1b[33mwarning: sandbox skipped for tool.py\x1b[0m\nok\nwarning: sandbox skipped for tool.py\n'
    skipped = finding('warning', title='Sandbox execution skipped: looks destructive')

    ran = build_report({'source': SRC, 'findings': [skipped]}, ATTESTATION, profile_ran, runner='docker', stderr=stderr)
    assert ran.sandbox == 'ran with docker'
    assert ran.notes[0] == 'warning: sandbox skipped for tool.py'
    assert len(ran.notes) == 2 and 'allow_write_tools=true' in ran.notes[1]

    idle = build_report({'source': SRC, 'findings': []}, ATTESTATION, {'tools': [{'path': 'tool.py'}]}, runner='docker')
    assert idle.sandbox.startswith('requested with docker, but no tool ran')
    assert idle.notes == []


def test_probe_args():
    assert probe_args('autofix', '.', None, None, False) == [
        'autofix', 'fix', '--source', '.', '--no-sign', '--output', 'json',
    ]
    assert probe_args('autofix', 'tools/x', [' tool.py ', ''], 'docker', True) == [
        'autofix', 'fix', '--source', 'tools/x', '--no-sign', '--output', 'json',
        '--entrypoint', 'tool.py', '--sandbox', '--runner', 'docker', '--allow-write-tools',
    ]
