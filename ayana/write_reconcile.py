"""Read-only observations for a deliberately small set of safe shell retries.

An image being present cannot prove that a mutable tag was just updated. Keep
the original unknown result and only establish that this exact pull is safe
to retry; never run the pull or infer success from an assistant's explanation.
"""
from __future__ import annotations

import hashlib
import json
import re
import shlex

from .agent_authority import resolve_authority
from .session_bridge import SessionBridge
from .transport import session_ssh_scope


_PULL = re.compile(r"\s*docker[ \t]+pull[ \t]+([A-Za-z0-9][A-Za-z0-9._:/@-]{0,250})[ \t]*\Z")


def pull_image(command: str) -> str:
    match = _PULL.fullmatch(command)
    return match.group(1) if match else ""


def recover_host_operation(db, row: dict) -> dict:
    """Recover legacy facts only when the full ledger fingerprints match."""
    for audit in db.query(
        "SELECT detail_json FROM audit_log WHERE action_id=? AND asset_id=? "
        "AND entry='mcp_host_exec_write' ORDER BY id DESC LIMIT 10",
        (row['action_key'], row['target']),
    ):
        try:
            facts = json.loads(audit['detail_json'])
            command = facts['command']
            if not pull_image(command) or facts.get('session_id') != row['session_id']:
                continue
            channel = 'write' if facts.get('purpose') == 'execute' else 'read'
            generation = int(facts.get('generation') or 0)
            # claim_write hashes the exact ledger payload, including its owner.
            payload = {'command': command, 'channel': channel}
            if row['session_id']:
                payload['_ayana_session_id'] = row['session_id']
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False,
                                                default=str).encode()).hexdigest()[:16]
            context = f'mcp-host-exec:generation:{generation}' if generation else 'mcp-host-exec'
            expected = SessionBridge.make_action_key(None, row['target'], 'exec_shell',
                {'command': command, 'channel': channel, 'classified': 'write'}, context=context)
            if digest != row['params_hash'] or expected != row['action_key']:
                continue
            return {'tool': 'host.exec', 'arguments': {'asset_id': row['target'],
                    'command': command, 'channel': channel},
                    'ssh_account_group': facts.get('ssh_account_group') or '',
                    'ssh_account': facts.get('ssh_account') or ''}
        except (KeyError, TypeError, ValueError):
            continue
    return {}


def observation_command(image: str) -> str:
    # The executable and every operation are fixed; image is a validated literal.
    code = '''import json,os,pathlib,subprocess
image=IMAGE
active=False
complete=True
for path in pathlib.Path('/proc').iterdir():
 if not path.name.isdigit(): continue
 try:
  argv=(path/'cmdline').read_bytes().split(b'\\0')
 except (FileNotFoundError,ProcessLookupError): continue
 except PermissionError:
  complete=False
  continue
 if argv and os.path.basename(os.fsdecode(argv[0]))=='docker' and b'pull' in argv[1:]: active=True
try:
 result=subprocess.run(['docker','image','inspect','--format','{{.Id}}','--',image],capture_output=True,text=True,timeout=8)
 available=result.returncode==0 and result.stdout.strip().startswith('sha256:')
 inspected=result.returncode in (0,1) and (available or 'No such image' in result.stderr)
except (OSError,subprocess.TimeoutExpired):
 available=False
 inspected=False
print(json.dumps({'pull_active':active,'process_view_complete':complete,'image_available':available,'image_inspected':inspected}))
'''.replace('IMAGE', repr(image), 1)
    return 'python3 -c ' + shlex.quote(code)


async def observe_host_write(db, transport, row: dict, operation: dict) -> dict:
    """Return facts to the observer; this function never changes a ledger row."""
    recovered = recover_host_operation(db, row)
    if recovered:
        # The audit includes the actual account used after SSH dispatch, while
        # the initial request only records the selected group before dispatch.
        operation = recovered
    elif not operation.get('ssh_account'):
        operation = {}
    args = operation.get('arguments') or {}
    image = pull_image(str(args.get('command') or ''))
    if operation.get('tool') != 'host.exec' or not image:
        return {'status': 'unsupported', 'message': '这条历史命令没有可自动确认的执行凭据，系统会保留结果保护；请由维护人员查看技术详情。'}
    if args.get('asset_id') != row['target'] or not row['session_id']:
        return {'status': 'blocked', 'message': '操作记录与目标主机不一致，系统已停止自动处理。'}
    try:
        group = resolve_authority(db, row['session_id'])['ssh_account_group']
        original_group = operation.get('ssh_account_group') or ''
        if not original_group or group != original_group:
            return {'status': 'blocked', 'message': '执行时的账号组与当前设置不同，暂时无法自动确认下载结果。'}
        endpoint_sql = ('SELECT id,host,port,username,credential_id,host_key_sha256,updated_at '
                        'FROM ssh_endpoints WHERE asset_id=? AND role=? AND enabled=1')
        endpoint = db.query_one(endpoint_sql, (row['target'], group))
        if (not endpoint or float(endpoint['updated_at']) > float(row['created_at'])
                or endpoint['username'] != operation.get('ssh_account')):
            return {'status': 'blocked', 'message': '执行后主机连接信息发生过变化，无法将当前主机状态当作原操作的依据。'}
        endpoint_identity = dict(endpoint)
        with session_ssh_scope(db, row['session_id']):
            result = await transport.exec_shell(row['target'], observation_command(image),
                                                15, channel='read')
        observed_endpoint = db.query_one(endpoint_sql, (row['target'], group))
        if (not observed_endpoint or dict(observed_endpoint) != endpoint_identity
                or resolve_authority(db, row['session_id'])['ssh_account_group'] != group):
            return {'status': 'blocked', 'message': '检查期间主机连接或账号组发生变化，系统保留原有结果保护。'}
        if not result.ok or result.returncode != 0 or result.timed_out:
            raise ValueError('observation unavailable')
        if (getattr(result, 'account_group', '') != original_group
                or not operation.get('ssh_account')
                or getattr(result, 'account', '') != operation['ssh_account']):
            raise ValueError('observation identity changed')
        facts = json.loads(result.output)
        if any(type(facts.get(key)) is not bool for key in
               ('pull_active', 'process_view_complete', 'image_available', 'image_inspected')):
            raise ValueError('invalid observation')
        if facts['pull_active']:
            return {'status': 'pending', 'message': '主机上还有镜像下载进程，系统会继续检查，暂不重复下载。'}
        if not facts['process_view_complete'] or not facts['image_inspected']:
            raise ValueError('incomplete observation')
        return {'outcome': 'retry_safe', 'evidence': {
            'kind': 'docker_pull_retry_safe', 'image': image, **facts,
            'summary': '下载进程已结束；原始下载结果仍未确认，镜像拉取可安全重试，已解除本次操作阻塞。'}}
    except Exception:
        return {'status': 'pending', 'message': '暂时无法读取主机上的下载状态，系统会自动重查。'}
