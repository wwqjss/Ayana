"""Opt-in real MiMo/MCP permission probe on one isolated Ayana session.

Runs four sequential native tool calls in one turn. Changes permissions through
the actual Web business handlers while that same receipt is running. Only the
probe's Incident notes are mutated; no SSH command or production setting changes.
The private local adapter supplies an isolated administrator, not browser auth.
"""
from __future__ import annotations
import argparse
import asyncio
import json
import os
from pathlib import Path
import secrets
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))


async def run(config_path: str) -> dict:
    from ayana.config import load_config
    from ayana.db import Database
    from ayana.duty_session import DutySessionManager
    from ayana.agent_authority import resolve_authority
    from ayana.agent_tui import AgentTuiManager
    from ayana.mimo_admin import MimoAdmin
    from ayana.mimo_runtime_config import runtime_paths, verified_runtime
    from ayana.mimo_serve import MimoServeClient, normalize_receipt_status
    from ayana.session_bridge import SessionBridge
    from ayana.incidents import IncidentService
    from ayana.web import WebApp
    cfg=load_config(config_path);paths=runtime_paths(cfg);db=Database(cfg['db_path'])
    duty=DutySessionManager(db);actor='authority-probe-'+secrets.token_hex(5)
    admin=MimoAdmin(mimo_bin=str(cfg.get('mimo_bin') or (cfg.get('auto_investigate') or {}).get('mimo_bin') or 'mimo'),workdir=paths['workdir'],config_dir=str(cfg.get('mimo_config_dir') or ''))
    runtime=lambda:verified_runtime(cfg,db,admin)
    native=MimoServeClient(base_url='http://127.0.0.1:'+str(cfg.get('mimo_serve_port') or 6290),password=str(cfg.get('mimo_serve_password') or cfg.get('webhook_token') or ''),directory=paths['workdir'])
    manager=AgentTuiManager(db,lambda:native,mimo_bin=admin._bin(),workdir=paths['workdir'],home=paths['home'],state_dir=paths['state_dir']+'/tui',runtime_resolver=runtime,redactor_factory=admin.redactor)
    bridge=SessionBridge(db,duty=duty);incidents=IncidentService(db)
    sid=duty.create(origin='manual',title='权限验收 '+actor,created_by=actor)['session_id']
    # Only the probe's own baseline. Never change the duty global configuration.
    db.execute("UPDATE duty_sessions SET access_mode='readonly',approval_mode='manual' WHERE id=?",(sid,))
    iid='inc_probe_'+secrets.token_hex(6);t=time.time()
    db.execute("INSERT INTO incidents(id,title,status,stage,created_at,updated_at) VALUES(?,?,'open','manual',?,?)",(iid,'隔离权限验收 '+actor,t,t))
    duty.join_incident(sid,iid)
    remote=await native.create_session(title='Ayana authority acceptance')
    rid=remote['session_id'];bridge._set_remote(sid,remote_session_id=rid,status='active')
    binding=await manager.ensure(sid,rid)
    connection='probe-'+secrets.token_hex(12)
    manager._connections[connection]={'session_id':sid,'username':actor}
    handler=WebApp.__new__(WebApp)
    handler.db,handler.duty,handler.agent_tui=db,duty,manager
    handler.session_bridge,handler.incidents=bridge,incidents
    handler.transport=handler.prom=handler.actions=None
    handler._require_admin=lambda request:{'username':actor,'is_admin':True}
    handler._check_csrf=lambda *args:None
    handler._agent_session_require=lambda user,current,**kwargs:duty.get(current)
    class Request:
        match_info={'sid':sid}
        def __init__(self,body):self.body=body
        async def json(self):return self.body
    async def change(**modes):
        response=await handler.api_agent_session_permissions(Request({'connection_id':connection,'revision':resolve_authority(db,sid)['revision'],**modes}))
        result=json.loads(response.text)
        if response.status!=200 or not result.get('ok'):raise RuntimeError('permission_change_failed:'+str(result.get('error')))
        return result['effective_permissions']
    initial=manager.acquire_control(sid,actor,connection)['effective_permissions']
    if (initial['access_mode'],initial['approval_mode'])!=('readonly','manual'):raise RuntimeError('inheritance_mismatch')
    last=int(db.query_one('SELECT COALESCE(MAX(id),0) n FROM audit_log')['n'])
    changes=[];audit=[];step=0;receipt_id='';settled=False
    try:
        prompt=(f'这是授权集成测试，仅操作隔离 Incident {iid}。请严格按顺序调用四次 ayana_incident_note，每次等工具返回后再进行下一次，禁止并行。'
            '第1次text=authority-step-1，第2次text=authority-step-2，第3次text=authority-step-3，第4次text=authority-step-4。'
            '拒绝或等待审批是预期测试结果，仍须继续下一次。不要重试，不调用其他工具、不执行SSH、不关单。四次后简短报告每次真实返回结果。')
        receipt=await native.prompt_async(rid,prompt,agent='ayana',message_id='msg_'+secrets.token_hex(14),model=str(runtime().get('model') or ''))
        receipt_id=receipt['receipt_id'];duty.record_receipt(sid,rid,receipt_id,origin='authority_probe')
        duty.set_runtime_state(sid,'running',receipt_id=receipt_id,receipt_status='accepted')
        deadline=time.monotonic()+300
        heartbeat=time.monotonic()
        expected=['rejected_readonly','awaiting_approval','success','rejected_readonly']
        while time.monotonic()<deadline:
            if time.monotonic()>=heartbeat:
                if not manager._has_control(sid,actor,connection,renew=True):raise RuntimeError('probe_control_expired')
                heartbeat=time.monotonic()+15
            for row in db.query('SELECT id,entry,detail_json FROM audit_log WHERE id>? ORDER BY id',(last,)):
                last=max(last,row['id'])
                detail=json.loads(row['detail_json'] or '{}')
                if row['entry']!='mcp_host_exec_write' or detail.get('authority_session_id')!=sid:continue
                if detail.get('approved_write'):continue
                audit.append({'id':row['id'],**detail})
                if step>=4 or detail.get('state')!=expected[step]:raise RuntimeError('unexpected_tool_authorization:'+str(detail.get('state')))
                if step==0:changes.append(await change(access_mode='readwrite',approval_mode='manual'))
                elif step==1:
                    pending=db.query_one("SELECT incident_id,action_key FROM session_write_ops WHERE session_id=? AND status='awaiting_approval'",(sid,))
                    if not pending:raise RuntimeError('missing_pending_write')
                    response=await handler.api_agent_pending_approve(Request(dict(pending)))
                    result=json.loads(response.text)
                    if result.get('exec_state')!='success':raise RuntimeError('approved_probe_did_not_execute')
                    changes.append(await change(approval_mode='automatic'))
                elif step==2:changes.append(await change(access_mode='readonly'))
                step+=1
            status=await native.receipt(rid,receipt_id)
            state=normalize_receipt_status(status)
            if state in ('completed','failed','cancelled'):
                settled=True
                db.execute('UPDATE agent_runtime_receipts SET status=?,updated_at=? WHERE receipt_id=?',(state,time.time(),receipt_id))
                duty.set_runtime_state(sid,'idle',receipt_id=receipt_id,receipt_status=state)
                if state!='completed' or step!=4:raise RuntimeError('incomplete_native_tool_probe:'+str(step))
                break
            await asyncio.sleep(.025)
        if not settled:raise RuntimeError('native_receipt_still_running')
        history=await native.messages(rid,limit=100)
        tools=[p for m in history for p in m.get('parts',[]) if p.get('type')=='tool']
        after=await manager.status(sid)
        same=all(after['binding'].get(k)==binding.get(k) for k in ('remote_session_id','engine_pid','pane_pid','pane_started_at','runtime_id'))
        if not same:raise RuntimeError('runtime_changed_during_switch')
        restored=manager.release_control(sid,actor,connection)['effective_permissions']
        if (restored['access_mode'],restored['approval_mode'])!=('readonly','manual'):raise RuntimeError('release_did_not_restore')
        result={'passed':True,'session_id':sid,'remote_session_id':rid,'incident_id':iid,'receipt_id':receipt_id,'one_native_turn':True,'same_engine_and_pane':same,
                'initial_permissions':initial,'live_changes':changes,'restored_permissions':restored,'authorization_results':[r['state'] for r in audit],
                'native_tools':tools,'audit':audit,'binding':after['binding'],'private_auth_adapter':True,'at':time.time()}
        path=Path(paths['state_dir'])/'authority-real-proof.json';path.write_text(json.dumps(result,ensure_ascii=False,indent=2));path.chmod(0o600)
        return {k:v for k,v in result.items() if k not in ('native_tools','audit')}
    finally:
        manager.release_control(sid,actor,connection)
        manager._connections.pop(connection,None)
        if settled:
            incidents.close_manual(iid,actor_type='web_user',actor=actor,reason='isolated_authority_acceptance_finished')
            duty.archive_session(sid,reason='isolated_authority_acceptance_finished')
        db.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',default='/etc/ayana/config.json');parser.add_argument('--execute-probe',required=True,action='store_true');args=parser.parse_args()
    if os.name!='posix' or os.geteuid()==0:parser.error('Run as the unprivileged Ayana account')
    print(json.dumps(asyncio.run(run(args.config)),ensure_ascii=False,indent=2))
