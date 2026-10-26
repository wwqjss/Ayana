"""Unified settings backend contracts; no production, SSH or model requests."""
from __future__ import annotations
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from aiohttp import web
from aiohttp.test_utils import TestServer
from ayana.auto_investigate import AutoInvestigator, CONCLUSION_PROMPT, DECISION_PROMPT
from ayana.db import Database, now
from ayana.mimo_admin import MimoAdmin
from ayana.ops_constraints import OpsConstraints, DEFAULT_CONSTRAINTS
from ayana.prom import PromClient, PromError
from ayana.settings_admin import PromptSettings, discover_skills, check_update
from ayana.web import SESSION_COOKIE, WebApp


class PromptVersionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(ignore_cleanup_errors=True);self.addCleanup(self.tmp.cleanup)
        self.db=Database(Path(self.tmp.name)/'test.db');self.addCleanup(self.db.close)
        self.store=PromptSettings(self.db)

    def test_defaults_are_explicit_and_schema_unchanged(self):
        overview=self.store.overview()
        self.assertEqual([item['key'] for item in overview['items']],['investigation','decision','constraints'])
        self.assertTrue(all(item['current']['is_default'] for item in overview['items']))
        self.assertEqual(self.store.current('investigation')['text'],CONCLUSION_PROMPT)
        self.assertEqual(self.db.schema_version(),22)

    def test_save_and_restore_create_independent_audited_versions(self):
        first=self.store.save('investigation','first investigation',actor='admin')
        second=self.store.save('investigation','second investigation',actor='admin')
        restored=self.store.restore('investigation',first['id'],actor='admin')
        self.assertGreater(restored['id'],second['id'])
        self.assertEqual(restored['text'],'first investigation')
        self.assertEqual(self.store.current('decision')['text'],DECISION_PROMPT)
        versions=self.store._rows('investigation')
        self.assertEqual(sum(row['active'] for row in versions),1)
        self.assertEqual(len(versions),3)
        audit=[dict(row) for row in self.db.query('SELECT detail_json FROM audit_log')]
        self.assertEqual(len(audit),3)
        self.assertNotIn('first investigation',json.dumps(audit))

    def test_restore_default_is_a_new_version_and_keeps_history(self):
        self.store.save('decision','custom',actor='admin')
        restored=self.store.restore('decision',0,actor='admin')
        self.assertTrue(restored['is_default'])
        self.assertEqual(restored['text'],DECISION_PROMPT)
        self.assertEqual(len(self.store._rows('decision')),2)

    def test_restore_cannot_read_another_prompt_kind(self):
        row=self.store.save('decision','decision only',actor='admin')
        with self.assertRaisesRegex(ValueError,'version_not_found'):
            self.store.restore('investigation',row['id'],actor='admin')

    def test_invalid_inputs_do_not_change_current_or_create_versions(self):
        for key,text,note in (('unknown','x',''),('investigation','',''),('decision','x'*20001,''),('constraints','bad\x00text',''),('decision','x',[]),('decision','x','n'*301)):
            with self.subTest(key=key,text_type=type(text).__name__),self.assertRaises(ValueError):
                self.store.save(key,text,actor='admin',change_note=note)
        for version in (-1,True,None,'1'):
            with self.subTest(version=version),self.assertRaises(ValueError):self.store.restore('decision',version,actor='admin')
        self.assertEqual(self.db.query_one('SELECT count(*) n FROM config_versions')['n'],0)

    def test_draft_constraints_never_override_active_or_default(self):
        ops=OpsConstraints(self.db)
        ops.save('draft only',actor='admin',activate=False)
        self.assertEqual(ops.current()['text'],DEFAULT_CONSTRAINTS)
        self.assertEqual(self.store.current('constraints')['text'],DEFAULT_CONSTRAINTS)
        active=self.store.save('constraints','active rules',actor='admin')
        for i in range(22):ops.save('draft '+str(i),actor='admin',activate=False)
        self.assertEqual(ops.current()['text'],'active rules')
        self.assertEqual(self.store.current('constraints')['id'],active['id'])

    def test_runtime_builders_read_new_versions_and_constraints_at_next_call(self):
        t=now();self.db.execute("INSERT INTO incidents(id,title,asset_id,object_id,created_at,updated_at) VALUES('i','incident','host','obj',?,?)",(t,t))
        runtime=AutoInvestigator(self.db)
        before=runtime._build_invest_prompt('i',round_no=1)
        self.store.save('investigation','CUSTOM INVESTIGATION',actor='admin')
        self.store.save('decision','CUSTOM DECISION',actor='admin')
        self.store.save('constraints','CURRENT SOFT RULES',actor='admin')
        after=runtime._build_invest_prompt('i',round_no=2)
        decision=runtime._build_decision_prompt('i',{'facts':[]})
        self.assertNotIn('CUSTOM INVESTIGATION',before)
        self.assertIn('CUSTOM INVESTIGATION',after)
        self.assertIn('CURRENT SOFT RULES',after)
        self.assertIn('CUSTOM DECISION',decision)
        self.assertIn('CURRENT SOFT RULES',decision)
        self.assertIn('Incident i',after)

    def test_concurrent_saves_leave_one_active_version(self):
        with ThreadPoolExecutor(max_workers=4) as executor:
            rows=list(executor.map(lambda number:self.store.save('decision','content '+str(number),actor='admin'),range(8)))
        self.assertEqual(len(self.store._rows('decision')),8)
        self.assertEqual(sum(row['active'] for row in self.store._rows('decision')),1)

    def test_audit_failure_rolls_back_new_version_and_activation(self):
        self.store.save('decision','original',actor='admin')
        with patch.object(self.db,'audit',side_effect=RuntimeError('private error')):
            with self.assertRaises(RuntimeError):self.store.save('decision','replacement',actor='admin')
        self.assertEqual(self.store.current('decision')['text'],'original')
        self.assertEqual(len(self.store._rows('decision')),1)


    def test_old_and_new_constraints_apis_share_one_active_version(self):
        legacy=OpsConstraints(self.db)
        legacy.save('legacy first',actor='legacy')
        first=self.store.current('constraints')
        self.assertEqual(first['text'],'legacy first')
        current=self.store.save('constraints','new center version',actor='admin')
        self.assertEqual(legacy.current()['version'],current['id'])
        legacy.activate(first['id'],actor='legacy')
        self.assertEqual(self.store.current('constraints')['id'],first['id'])
        self.assertEqual(sum(row['active'] for row in self.store._rows('constraints')),1)

    def test_legacy_save_audit_failure_rolls_back_all_writes(self):
        first=self.store.save('constraints','original active',actor='admin')
        with patch.object(self.db,'audit',side_effect=RuntimeError('private audit failure')):
            with self.assertRaises(RuntimeError):OpsConstraints(self.db).save('must rollback',actor='legacy')
        self.assertEqual(self.store.current('constraints')['id'],first['id'])
        self.assertEqual(len(self.store._rows('constraints')),1)

    def test_legacy_activate_audit_failure_restores_previous_active(self):
        first=self.store.save('constraints','first',actor='admin')
        second=self.store.save('constraints','second',actor='admin')
        with patch.object(self.db,'audit',side_effect=RuntimeError('private audit failure')):
            with self.assertRaises(RuntimeError):OpsConstraints(self.db).activate(first['id'],actor='legacy')
        self.assertEqual(self.store.current('constraints')['id'],second['id'])
        self.assertEqual(sum(row['active'] for row in self.store._rows('constraints')),1)

    def test_new_writer_waits_for_entire_legacy_save_or_activate_transaction(self):
        # Hold the old API in its audit step. The new writer must not commit
        # through either the shared Database or an independent MCP connection.
        for independent in (False,True):
            for operation in ('save','activate'):
                with self.subTest(independent=independent,operation=operation):
                    legacy=OpsConstraints(self.db)
                    first=self.store.save('constraints','restore target',actor='admin')
                    self.store.save('constraints','initial active',actor='admin')
                    other=Database(self.db.path) if independent else self.db
                    if independent:self.addCleanup(other.close)
                    new_store=PromptSettings(other)
                    entered=threading.Event();release=threading.Event();attempted=threading.Event()
                    original_audit=self.db.audit
                    def audit(actor_type,actor_id,entry,**kwargs):
                        if actor_id=='legacy':
                            entered.set()
                            if not release.wait(3):raise RuntimeError('test did not release transaction')
                        return original_audit(actor_type,actor_id,entry,**kwargs)
                    def old_write():
                        if operation=='save':return legacy.save('legacy concurrent',actor='legacy')
                        return legacy.activate(first['id'],actor='legacy')
                    def new_write():
                        attempted.set()
                        return new_store.save('constraints','new concurrent',actor='new')
                    with patch.object(self.db,'audit',side_effect=audit),ThreadPoolExecutor(max_workers=2) as executor:
                        old=executor.submit(old_write)
                        try:
                            self.assertTrue(entered.wait(3))
                            new=executor.submit(new_write)
                            self.assertTrue(attempted.wait(3))
                            # A bounded wait observes whether the second API
                            # escaped the first one's still-uncommitted audit.
                            from concurrent.futures import wait
                            done,_=wait([new],timeout=0.1)
                            self.assertEqual(done,set())
                        finally:
                            release.set()
                        old.result(timeout=3);new.result(timeout=3)
                    self.assertEqual(sum(row['active'] for row in self.store._rows('constraints')),1)
                    self.assertEqual(self.store.current('constraints')['text'],'new concurrent')
                    self.assertEqual(legacy.current()['text'],'new concurrent')


class SkillsInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(ignore_cleanup_errors=True);self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.home=self.base/'home';self.workdir=self.base/'project'
        self.home.mkdir();self.workdir.mkdir()

    def skill(self,parent,name='check'):
        path=parent/name/'SKILL.md';path.parent.mkdir(parents=True)
        path.write_text('---\nname: sample-check\ndescription: Read service facts\n---\nprivate body that must not be returned',encoding='utf-8')
        return path

    def test_actual_files_only_and_loading_not_claimed(self):
        path=self.skill(self.home/'.config/mimocode/skills')
        self.skill(self.workdir/'.agents/skills','project-check')
        result=discover_skills(home=self.home,workdir=self.workdir)
        self.assertEqual(len(result['items']),2)
        self.assertTrue(all(item['loaded'] is None and item['status']=='discovered' for item in result['items']))
        self.assertTrue(any(item['path']==str(path) for item in result['items']))
        self.assertNotIn('private body',json.dumps(result))
        self.assertEqual(result['items'][0]['name'],'sample-check')

    def test_missing_and_oversized_skill_files_are_not_invented(self):
        result=discover_skills(home=self.home,workdir=self.workdir)
        self.assertEqual(result['items'],[])
        path=self.skill(self.home/'.mimocode/skills')
        path.write_bytes(b'x'*65537)
        self.assertEqual(discover_skills(home=self.home,workdir=self.workdir)['items'],[])

    def test_symlink_root_ancestor_cannot_escape_allowed_home(self):
        outside=self.base/'outside';outside.mkdir();self.skill(outside/'skills')
        link=self.home/'.agents'
        try:link.symlink_to(outside,target_is_directory=True)
        except OSError:self.skipTest('symlink not supported')
        result=discover_skills(home=self.home,workdir=self.workdir)
        self.assertEqual(result['items'],[])
        self.assertFalse(next(root for root in result['roots'] if root['source']=='Agents 全局')['exists'])


class SettingsApiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(ignore_cleanup_errors=True);self.addCleanup(self.tmp.cleanup)
        self.db=Database(Path(self.tmp.name)/'web.db');self.addCleanup(self.db.close)
        self.session={'username':'admin','user_id':1,'is_admin':True,'csrf_token':'csrf','must_change_password':False}
        self.auth=SimpleNamespace(get_session=lambda sid,**kw:self.session if sid=='valid' else None,totp_enabled=lambda username:True)
        self.admin=MimoAdmin(workdir=self.tmp.name)
        self.admin.status=AsyncMock(return_value={'version':'0.1.15','exists':True})
        self.app=WebApp(self.db,self.auth,None,None,None,None,None,static_dir=Path(self.tmp.name),version='0.8.0',mimo_admin=self.admin)

    def req(self,body=None,*,method='POST',csrf='csrf',origin='',authenticated=True,path='/api/settings/prompts'):
        return SimpleNamespace(json=AsyncMock(return_value=body),cookies={SESSION_COOKIE:'valid' if authenticated else ''},remote='',method=method,
                               headers={'X-CSRF-Token':csrf,'Origin':origin,'Host':'ayana.test'},rel_url=SimpleNamespace(path=path,query={}))

    async def test_private_endpoints_require_auth_and_admin(self):
        handlers=(self.app.api_settings_prompts_get,self.app.api_settings_prompts_save,self.app.api_settings_prompts_restore,self.app.api_settings_skills,self.app.api_settings_updates_check)
        for handler in handlers:
            with self.assertRaises(web.HTTPUnauthorized):await handler(self.req({},authenticated=False))
        self.session['is_admin']=False
        for handler in handlers:
            with self.assertRaises(web.HTTPForbidden):await handler(self.req({}))
        self.assertEqual(self.db.query_one('SELECT count(*) n FROM config_versions')['n'],0)

    async def test_write_endpoints_keep_csrf_and_origin_checks(self):
        for handler in (self.app.api_settings_prompts_save,self.app.api_settings_prompts_restore,self.app.api_settings_updates_check):
            for kwargs in ({'csrf':''},{'origin':'https://evil.test'}):
                with self.assertRaises(web.HTTPForbidden):await handler(self.req({},**kwargs))

    async def test_forced_password_change_cannot_access_settings(self):
        self.session['must_change_password']=True
        with self.assertRaises(web.HTTPForbidden):await self.app.api_settings_prompts_get(self.req(method='GET'))

    async def test_prompt_save_restore_and_get_contract(self):
        saved=await self.app.api_settings_prompts_save(self.req({'key':'investigation','text':'new rules','change_note':'test'}))
        data=json.loads(saved.text);self.assertTrue(data['ok']);self.assertEqual(data['effect'],'next_call')
        overview=json.loads((await self.app.api_settings_prompts_get(self.req(method='GET'))).text)
        self.assertEqual(overview['items'][0]['current']['text'],'new rules')
        restored=json.loads((await self.app.api_settings_prompts_restore(self.req({'key':'investigation','version_id':0}))).text)
        self.assertTrue(restored['current']['is_default'])

    async def test_malformed_fields_and_extra_paths_are_rejected(self):
        for body in ([],None,'bad',{'key':'decision','text':{},'path':'/etc/secret'}):
            response=await self.app.api_settings_prompts_save(self.req(body));self.assertEqual(response.status,400)
        response=await self.app.api_settings_prompts_save(self.req({'key':'decision','text':{}}));self.assertEqual(response.status,400)
        response=await self.app.api_settings_prompts_restore(self.req({'key':'decision','version_id':True}));self.assertEqual(response.status,400)
        req=self.req({});req.json.side_effect=ValueError('private-key bad JSON')
        response=await self.app.api_settings_prompts_save(req);self.assertNotIn('private-key',response.text)

    async def test_storage_failure_is_sanitized(self):
        with patch('ayana.settings_admin.PromptSettings.save',side_effect=OSError('dummy-secret')):
            response=await self.app.api_settings_prompts_save(self.req({'key':'decision','text':'x'}))
        self.assertEqual(response.status,500);self.assertNotIn('dummy-secret',response.text)

    async def test_about_versions_are_real_and_available_to_nonadmin(self):
        self.session['is_admin']=False
        response=await self.app.api_settings_about(self.req(method='GET'))
        data=json.loads(response.text);self.assertEqual(data['mimocode_version'],'0.1.15')
        self.assertEqual(data['ayana_version'],'0.8.0');self.assertEqual(data['project_url'],'https://github.com/wwqjss/Ayana')
        self.admin.status.assert_awaited_once()

    async def test_me_only_adds_boolean_two_factor_state(self):
        response=await self.app.api_me(self.req(method='GET',path='/api/me'))
        data=json.loads(response.text)
        self.assertIs(data['user']['totp_enabled'],True)
        self.assertNotIn('secret',response.text)

    async def test_skill_inventory_does_not_return_metadata_key_echo(self):
        result={'ok':True,'items':[{'name':'Bearer dummy-private-key','description':'test'}],'roots':[]}
        with patch('ayana.settings_admin.discover_skills',return_value=result),patch.object(self.admin,'_redact',side_effect=lambda text:text.replace('dummy-private-key','[redacted]')):
            response=await self.app.api_settings_skills(self.req(method='GET'))
        self.assertNotIn('dummy-private-key',response.text)

    async def test_skill_quoted_and_backslash_keys_are_redacted_before_json_escaping(self):
        key='dummy-"quoted\\backslash-key'
        self.admin.config_path=lambda config_dir='':Path(self.tmp.name)/'mimocode.jsonc'
        self.admin.apply_provider(provider_id='xiaomi',api_key=key,base_url='https://api.example.test/v1',model='test')
        result={'ok':True,'items':[{'name':key,'description':'contains '+key}],
                'roots':[],'nested':{key:[key,'Bearer '+key]}}
        with patch('ayana.settings_admin.discover_skills',return_value=result):
            response=await self.app.api_settings_skills(self.req(method='GET'))
        decoded=json.loads(response.text)
        self.assertEqual(decoded['items'][0]['name'],'[redacted]')
        self.assertNotIn(key,decoded['items'][0]['description'])
        self.assertNotIn(key,decoded['nested'])
        self.assertEqual(decoded['nested']['[redacted]'][0],'[redacted]')
        self.assertNotIn(json.dumps(key,ensure_ascii=False)[1:-1],response.text)

    async def test_update_check_is_readonly_and_cannot_target_arbitrary_url(self):
        with patch('ayana.settings_admin.check_update',new=AsyncMock(return_value={'ok':True,'result':'no_release'})) as check:
            response=await self.app.api_settings_updates_check(self.req({}));self.assertTrue(json.loads(response.text)['ok'])
            check.assert_awaited_once_with('0.8.0')
            response=await self.app.api_settings_updates_check(self.req({'url':'http://127.0.0.1/'}));self.assertEqual(response.status,400)
        self.assertEqual(self.db.query_one('SELECT count(*) n FROM actions')['n'],0)

    async def test_actual_scalar_query_marks_global_connection_available(self):
        self.app.prom=PromClient('http://unused')
        self.app.prom._get=AsyncMock(return_value={'status':'success','data':{'resultType':'scalar','result':[1234.5,'1']}})
        response=await self.app.api_settings_global_get(self.req(method='GET',path='/api/settings/global'))
        data=json.loads(response.text)
        self.assertTrue(data['prometheus_ok'])
        self.assertEqual(data['prometheus_error'],'')

    async def test_probe_never_returns_raw_exception(self):
        self.app.prom=SimpleNamespace(query=AsyncMock(side_effect=AttributeError("dummy-secret float has no get")))
        ok,message=await self.app._probe_prometheus()
        self.assertFalse(ok);self.assertNotIn('dummy-secret',message);self.assertNotIn('AttributeError',message)


class PromInstantQueryTests(unittest.IsolatedAsyncioTestCase):
    async def test_scalar_health_expression_is_a_valid_sample(self):
        client=PromClient('http://unused')
        client._get=AsyncMock(return_value={'status':'success','data':{'resultType':'scalar','result':[1234.5,'1']}})
        result=await client.query('1')
        self.assertEqual(result['result'],[{'metric':{},'value':1.0}])

    async def test_vector_contract_is_preserved(self):
        client=PromClient('http://unused')
        client._get=AsyncMock(return_value={'status':'success','data':{'resultType':'vector','result':[{'metric':{'job':'node'},'value':[1,'2']} ]}})
        self.assertEqual((await client.query('up'))['result'],[{'metric':{'job':'node'},'value':2.0}])

    async def test_malformed_scalar_vector_and_string_fail_cleanly(self):
        client=PromClient('http://unused')
        for data in ({'resultType':'scalar','result':[1]}, {'resultType':'scalar','result':[1,'wrong']}, {'resultType':'vector','result':[1]}, {'resultType':'string','result':[1,'text']}, []):
            client._get=AsyncMock(return_value={'status':'success','data':data})
            with self.subTest(data=data),self.assertRaises(PromError):await client.query('1')


class LocalUpdateCheckTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.mode='success';self.requests=[]
        async def release(request):
            self.requests.append(request.path)
            if self.mode=='redirect':raise web.HTTPTemporaryRedirect('/unwanted')
            if self.mode=='missing':return web.Response(status=404)
            if self.mode=='bad':return web.Response(text='dummy-private-provider-error')
            return web.json_response({'tag_name':'v0.9.0'})
        async def unwanted(request):
            self.requests.append(request.path);return web.Response(text='should not visit')
        app=web.Application();app.router.add_get('/release',release);app.router.add_get('/unwanted',unwanted)
        self.server=TestServer(app);await self.server.start_server();self.addAsyncCleanup(self.server.close)

    async def test_real_local_release_response_is_compared(self):
        with patch('ayana.settings_admin.RELEASE_URL',str(self.server.make_url('/release'))):result=await check_update('0.8.0')
        self.assertTrue(result['update_available']);self.assertEqual(result['latest_version'],'v0.9.0')
        self.assertEqual(self.requests,['/release'])

    async def test_redirect_is_not_followed(self):
        self.mode='redirect'
        with patch('ayana.settings_admin.RELEASE_URL',str(self.server.make_url('/release'))):result=await check_update('0.8.0')
        self.assertFalse(result['ok']);self.assertEqual(self.requests,['/release'])

    async def test_no_release_is_explicit_not_false_up_to_date(self):
        self.mode='missing'
        with patch('ayana.settings_admin.RELEASE_URL',str(self.server.make_url('/release'))):result=await check_update('0.8.0')
        self.assertTrue(result['ok']);self.assertEqual(result['result'],'no_release');self.assertNotIn('update_available',result)

    async def test_invalid_release_error_is_not_reflected(self):
        self.mode='bad'
        with patch('ayana.settings_admin.RELEASE_URL',str(self.server.make_url('/release'))):result=await check_update('0.8.0')
        self.assertFalse(result['ok']);self.assertNotIn('dummy-private',json.dumps(result))


if __name__=='__main__':unittest.main()
