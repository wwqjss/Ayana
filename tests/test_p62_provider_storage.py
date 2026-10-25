"""P6.2 private provider storage, binding and real local HTTP transport regressions."""
import asyncio
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aiohttp import web
from aiohttp.test_utils import TestServer
from ayana.db import Database
from ayana.mimo_admin import MimoAdmin


class PrivateConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)
        self.admin=MimoAdmin(config_dir=str(self.base/'config'))
        self.db=Database(self.base/'test.db')
        self.addCleanup(self.db.close)
        self.credentials={'provider_id':'xiaomi','base_url':'https://api.example.test/v1','model':'mimo-test','api_key':'dummy-test-key'}

    def save(self):
        self.admin.apply_provider(**self.credentials)
        self.admin.record_verification(self.db,self.credentials,{'ok':True,'result':'success','message':'connection verified'})

    def test_jsonc_preserves_comments_strings_mcp_permissions_and_model_options(self):
        path=self.admin.config_path();path.parent.mkdir()
        path.write_text('''{
          // existing managed and unrelated fields
          "mcp":{"ayana":{"command":["python","launcher.py"]}},
          "permission":{"bash":"deny",},
          "notes":"https://example.test/a//b/*literal*/",
          "provider":{"xiaomi":{"models":{"mimo-test":{"limit":{"context":1000}}}}},
        }''',encoding='utf-8')
        self.save();data=json.loads(path.read_text(encoding='utf-8'))
        self.assertEqual(data['mcp']['ayana']['command'],['python','launcher.py'])
        self.assertEqual(data['permission'],{'bash':'deny'})
        self.assertEqual(data['notes'],'https://example.test/a//b/*literal*/')
        self.assertEqual(data['provider']['xiaomi']['models']['mimo-test']['limit'],{'context':1000})
        self.admin.clear_provider();data=json.loads(path.read_text(encoding='utf-8'))
        self.assertIn('mcp',data);self.assertIn('permission',data)
        self.assertNotIn('apiKey',data['provider']['xiaomi']['options'])

    def test_malformed_or_duplicate_configuration_is_never_overwritten(self):
        path=self.admin.config_path();path.parent.mkdir()
        for raw in ('{"mcp":', '{"mcp":{},"mcp":{"bad":1}}','{"mcp":{},/*unfinished','[]'):
            with self.subTest(raw=raw):
                path.write_text(raw,encoding='utf-8')
                for operation in (lambda:self.admin.apply_provider(**self.credentials),self.admin.clear_provider):
                    with self.assertRaises(ValueError):operation()
                    self.assertEqual(path.read_text(encoding='utf-8'),raw)

    def test_failed_atomic_replace_keeps_original_and_removes_temporary(self):
        self.save();path=self.admin.config_path();original=path.read_bytes()
        with patch('ayana.mimo_admin.os.replace',side_effect=OSError('dummy private failure')):
            with self.assertRaisesRegex(ValueError,'provider_save_failed'):
                self.admin.apply_provider(**{**self.credentials,'api_key':'replacement-test'})
        self.assertEqual(path.read_bytes(),original)
        self.assertEqual(list(path.parent.glob('.mimocode-*.tmp')),[])

    def test_private_file_and_no_key_in_summary_or_runtime_errors(self):
        self.save();path=self.admin.config_path()
        if os.name=='posix':self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
        summary=json.dumps(self.admin.provider_summary())
        self.assertNotIn(self.credentials['api_key'],summary)
        self.assertTrue(self.admin.verification_state(self.db)['verified'])
        runtime=self.admin.runtime_configuration(self.db)
        self.assertEqual(runtime['model'],'xiaomi/mimo-test')
        self.assertEqual(runtime['config']['provider']['xiaomi']['options']['apiKey'],self.credentials['api_key'])

    def test_active_provider_is_selected_instead_of_first_entry(self):
        self.save();path=self.admin.config_path();data=json.loads(path.read_text())
        data['provider']={'first':{'options':{'apiKey':'other-dummy','baseURL':'https://other.example.test/v1'}},**data['provider']}
        path.write_text(json.dumps(data),encoding='utf-8')
        self.assertEqual(self.admin.resolve_provider()['provider_id'],'xiaomi')
        self.assertEqual(self.admin.resolve_provider()['api_key'],self.credentials['api_key'])

    def test_blank_key_preserves_selected_key_but_not_for_new_endpoint(self):
        self.save()
        resolved=self.admin.resolve_provider(model='mimo-new')
        self.assertEqual(resolved['api_key'],self.credentials['api_key'])
        with self.assertRaisesRegex(ValueError,'key_required_for_endpoint_change'):
            self.admin.resolve_provider(base_url='https://changed.example.test/v1')

    def test_any_current_credential_or_model_change_invalidates_verification(self):
        for field,value in (('apiKey','changed-test'),('baseURL','https://changed.example.test/v1'),('model','xiaomi/mimo-new')):
            with self.subTest(field=field):
                self.save();path=self.admin.config_path();data=json.loads(path.read_text())
                if field=='model':data[field]=value
                else:data['provider']['xiaomi']['options'][field]=value
                path.write_text(json.dumps(data),encoding='utf-8')
                self.assertFalse(self.admin.verification_state(self.db)['verified'])
                with self.assertRaisesRegex(ValueError,'provider_not_verified'):self.admin.runtime_configuration(self.db)

    def test_failed_retest_revokes_only_matching_saved_configuration(self):
        self.save()
        self.admin.record_verification(self.db,{**self.credentials,'api_key':'unsaved-other'}, {'ok':False,'result':'auth_failed'})
        self.assertTrue(self.admin.verification_state(self.db)['verified'])
        self.admin.record_verification(self.db,self.credentials,{'ok':False,'result':'auth_failed'})
        self.assertFalse(self.admin.verification_state(self.db)['verified'])

    def test_plain_legacy_boolean_cannot_certify_a_provider(self):
        self.admin.apply_provider(**self.credentials)
        self.admin.save_verification_state(self.db,{'verified':True})
        self.assertFalse(self.admin.verification_state(self.db)['verified'])

    def test_clearing_key_immediately_blocks_runtime_without_restart(self):
        self.save();self.admin.clear_provider()
        self.assertFalse(self.admin.verification_state(self.db)['verified'])
        with self.assertRaisesRegex(ValueError,'provider_not_verified'):self.admin.runtime_configuration(self.db)

    def test_private_or_credential_url_and_control_character_key_are_rejected(self):
        for url in ('http://api.example.test/v1','https://127.0.0.1/v1','https://169.254.169.254/v1','https://user:pass@api.example.test/v1','https://api.example.test/v1?token=dummy'):
            with self.subTest(url=url),self.assertRaises(ValueError):
                self.admin.resolve_provider(**{**self.credentials,'base_url':url})
        bad='dummy-private\r\nheader'
        res=self.admin.test_connection(base_url=self.credentials['base_url'],api_key=bad,model='m')
        self.assertFalse(res['ok']);self.assertNotIn(bad,json.dumps(res))

    def test_success_requires_a_real_model_reply_not_just_http_200(self):
        for raw in ('<html>proxy login</html>','{}','{"choices":[]}','{"error":{"message":"dummy-key"}}','{"choices":[{"message":{"content":""}}]}'):
            self.assertFalse(self.admin.classify_api_response(200,raw)['ok'])
        self.assertTrue(self.admin.classify_api_response(200,'{"choices":[{"message":{"content":"PONG"}}]}')['ok'])

    def test_management_output_redacts_the_saved_key(self):
        self.save();secret=self.credentials['api_key']
        self.assertNotIn(secret,self.admin._redact('error Bearer '+secret+' key='+secret))

    def test_verification_database_failure_is_not_silently_accepted(self):
        class FailedStore:
            def execute(self,*args):raise RuntimeError('dummy failure')
        with self.assertRaisesRegex(ValueError,'provider_state_save_failed'):
            self.admin.save_verification_state(FailedStore(),{'verified':True})


    def test_runtime_uses_one_verified_credential_snapshot(self):
        self.save()
        replacement={**self.credentials,'api_key':'unverified-replacement'}
        with patch.object(self.admin,'resolve_provider',side_effect=[self.credentials,replacement]) as resolve:
            runtime=self.admin.runtime_configuration(self.db)
        self.assertEqual(resolve.call_count,1)
        self.assertEqual(runtime['config']['provider']['xiaomi']['options']['apiKey'],self.credentials['api_key'])
        self.assertNotIn('unverified-replacement',json.dumps(runtime))


class LocalProviderTransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests=[];self.mode='success'
        async def completion(request):
            self.requests.append({'path':request.path,'auth':request.headers.get('Authorization'),'json':await request.json()})
            if self.mode=='redirect':raise web.HTTPTemporaryRedirect(location='/stolen')
            if self.mode=='auth':return web.json_response({'error':{'message':'dummy-test-key'}},status=401)
            if self.mode in ('chunked','oversized'):
                response=web.StreamResponse(headers={'Content-Type':'application/json'})
                await response.prepare(request)
                await response.write(b'{"choices":[')
                await asyncio.sleep(0.03)
                content='PONG' if self.mode=='chunked' else 'x'*65536
                await response.write(json.dumps({'message':{'content':content}}).encode()+b']}')
                await response.write_eof()
                return response
            return web.json_response({'choices':[{'message':{'content':'PONG'}}]})
        async def stolen(request):
            self.requests.append({'path':'stolen'});return web.Response(text='should never be reached')
        app=web.Application();app.router.add_post('/v1/chat/completions',completion);app.router.add_post('/stolen',stolen)
        self.server=TestServer(app);await self.server.start_server();self.addAsyncCleanup(self.server.close)
        self.admin=MimoAdmin()

    async def request(self):
        # Only this isolated local server bypasses public-endpoint checks; the
        # separate default-policy test above must still reject private targets.
        with patch('ayana.llm.LLMClient._endpoint_allowed',return_value=True),patch('ayana.llm.LLMClient._connector',return_value=None):
            return await asyncio.to_thread(self.admin.test_connection,base_url=str(self.server.make_url('/v1')),api_key='dummy-test-key',model='mimo-test')

    async def test_real_local_post_reaches_selected_model_once(self):
        result=await self.request();self.assertTrue(result['ok'])
        self.assertEqual(len(self.requests),1)
        self.assertEqual(self.requests[0]['json']['model'],'mimo-test')
        self.assertEqual(self.requests[0]['auth'],'Bearer dummy-test-key')
        self.assertNotIn('dummy-test-key',json.dumps(result))

    async def test_redirect_never_forwards_the_key(self):
        self.mode='redirect';result=await self.request()
        self.assertFalse(result['ok']);self.assertEqual(result['result'],'redirect_rejected')
        self.assertEqual(len(self.requests),1)

    async def test_provider_error_body_is_not_reflected(self):
        self.mode='auth';result=await self.request()
        self.assertEqual(result['result'],'auth_failed')
        self.assertNotIn('dummy-test-key',json.dumps(result))

    async def test_fragmented_response_is_read_until_eof(self):
        self.mode='chunked';result=await self.request()
        self.assertTrue(result['ok'])
        self.assertEqual(result['result'],'success')
        self.assertEqual(len(self.requests),1)

    async def test_fragmented_response_keeps_the_size_limit(self):
        self.mode='oversized';result=await self.request()
        self.assertFalse(result['ok'])
        self.assertEqual(result['result'],'invalid_response')
        self.assertEqual(len(self.requests),1)
