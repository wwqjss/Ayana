"""Request-scoped redaction stays safe without per-string configuration I/O."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from ayana.agent_tui import AgentTuiError, AgentTuiManager
from ayana.mimo_admin import MimoAdmin


class MimoRedactorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'mimocode.jsonc'
        self.admin = MimoAdmin(config_dir=self.tmp.name)
        self.write_keys('dummy-old-provider-key')

    def write_keys(self, *keys):
        self.path.write_text(json.dumps({'provider': {
            'test' + str(i): {'options': {'apiKey': key}}
            for i, key in enumerate(keys)
        }}), encoding='utf-8')

    def manager(self):
        return AgentTuiManager(Mock(), lambda: None,
            home=self.tmp.name, workdir=self.tmp.name,
            state_dir=str(Path(self.tmp.name) / 'state'),
            redactor_factory=self.admin.redactor)

    def test_full_catalog_traversal_reads_config_once_and_masks_every_leaf(self):
        catalog = {'models': [
            {'id': 'model-' + str(i), 'name': 'dummy-old-provider-key ' + str(i),
             'description': 'Bearer transient-secret',
             'options': {'apiKey': 'other-sensitive-field'}}
            for i in range(2500)
        ]}
        with patch.object(self.admin, '_read_config', wraps=self.admin._read_config) as read:
            result = self.manager()._sanitize(catalog)
        self.assertEqual(read.call_count, 1)
        text = json.dumps(result)
        self.assertNotIn('dummy-old-provider-key', text)
        self.assertNotIn('transient-secret', text)
        self.assertNotIn('other-sensitive-field', text)
        self.assertEqual(len(result['models']), 2500)
        self.assertEqual(result['models'][2499]['id'], 'model-2499')
        self.assertEqual(catalog['models'][0]['name'], 'dummy-old-provider-key 0')

    def test_next_response_refreshes_snapshot_after_key_rotation(self):
        manager = self.manager()
        with patch.object(self.admin, '_read_config', wraps=self.admin._read_config) as read:
            first = manager._sanitize({'message': 'dummy-old-provider-key'})
            self.write_keys('dummy-new-provider-key')
            second = manager._sanitize({'message': 'dummy-new-provider-key'})
        self.assertEqual(read.call_count, 2)
        self.assertEqual(first['message'], '[redacted]')
        self.assertEqual(second['message'], '[redacted]')

    def test_existing_response_snapshot_is_immutable(self):
        with patch.object(self.admin, '_read_config', wraps=self.admin._read_config) as read:
            first = self.admin.redactor()
            self.write_keys('dummy-new-provider-key')
            second = self.admin.redactor()
            self.assertEqual(first('dummy-old-provider-key'), '[redacted]')
            self.assertEqual(second('dummy-new-provider-key'), '[redacted]')
            for _ in range(100):
                first('safe string')
                second('safe string')
        self.assertEqual(read.call_count, 2)

    def test_overlapping_keys_are_masked_longest_first(self):
        self.write_keys('dummy-overlap', 'dummy-overlap-longer')
        self.assertEqual(self.admin.redactor()('dummy-overlap-longer'), '[redacted]')

    def test_snapshot_masks_bearer_tokens_without_provider_match(self):
        redact = self.admin.redactor()
        self.assertEqual(redact('Authorization: Bearer temporary-token\nnext'),
                         'Authorization: Bearer [redacted]\nnext')

    def test_malformed_configuration_fails_factory_and_hides_diagnostics(self):
        self.path.write_text('{invalid config containing dummy-old-provider-key', encoding='utf-8')
        with self.assertRaises(ValueError):
            self.admin.redactor()
        self.assertEqual(self.admin._redact('dummy-old-provider-key'), '[unavailable]')
        with self.assertRaises(AgentTuiError) as denied:
            self.manager()._sanitize({'message': 'dummy-old-provider-key'})
        self.assertEqual(denied.exception.code, 'redaction_unavailable')


if __name__ == '__main__':
    unittest.main()
