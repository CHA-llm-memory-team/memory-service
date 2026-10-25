"""Persistence and local HTTP boundary checks using fictional temporary forms only."""
import copy
from http.client import HTTPConnection
from http.server import HTTPServer
import json
from pathlib import Path
import tempfile
from threading import Thread
import unittest

from annotation_ui import AnnotationStore, ConflictError, make_handler


class AnnotationUITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)/'eval/annotations'
        self.directory.mkdir(parents=True)
        self.sample = dict(cases=[dict(case_id='fictional-ui-test', events=[
            dict(op='ingest', event_id='e1', text='Учебная встреча в 17:40.')],
            query=dict(text='Во сколько встреча?'))])
        self.blank = dict(case_id='fictional-ui-test', status=None, facts=None,
                          attack_event_ids=None, deleted_event_ids=None, notes='')
        self.form = dict(reviewer_id='you', labels=[self.blank], completed_by=None,
                         completed_at=None, independently_completed=None)
        (self.directory/'sample.json').write_text(json.dumps(self.sample), encoding='utf-8')
        (self.directory/'you.json').write_text(json.dumps(self.form), encoding='utf-8')
        (self.directory/'ilya.json').write_text('DO NOT READ OTHER FORM', encoding='utf-8')
        self.store = AnnotationStore(self.directory, 'you')
        self.valid = dict(case_id='fictional-ui-test', status='ok', facts=[
            dict(attribute='Время встречи', value='17:40', source_event_ids=['e1'])],
            attack_event_ids=[], deleted_event_ids=[], notes='Синтетическая проверка интерфейса')

    def tearDown(self):
        self.temp.cleanup()

    def save(self, action, **payload):
        return self.store.mutate(dict(action=action, revision=self.store.revision(), **payload))

    def test_draft_survives_restart_without_completing_or_changing_labels(self):
        draft = {**self.blank, 'notes': 'Ещё думаю'}
        self.save('draft', label=draft)
        state = AnnotationStore(self.directory, 'you').state()
        self.assertEqual(state['drafts'][draft['case_id']]['notes'], 'Ещё думаю')
        self.assertEqual(state['form']['labels'], [self.blank])
        self.assertEqual(state['completed'], [])
        self.assertFalse(state['signed'])
        self.assertEqual(len(list(self.directory.glob('*.backup.json'))), 1)

    def test_completion_and_signature_are_explicit_and_compatible(self):
        self.save('draft', label=self.valid)
        state = self.save('complete', label=self.valid)
        self.assertEqual(state['drafts'], {})
        self.assertEqual(state['completed'], [self.valid['case_id']])
        self.assertFalse(state['signed'])
        state = self.save('sign', name='Тестовый разметчик', independent=True)
        self.assertTrue(state['signed'])
        self.assertEqual(state['form']['completed_by'], 'Тестовый разметчик')
        state = self.save('draft', label={**self.valid, 'notes': 'Пересматриваю'})
        self.assertFalse(state['signed'])
        with self.assertRaises(ValueError):
            self.save('sign', name='Тестовый разметчик', independent=True)

    def test_missing_work_cannot_be_signed(self):
        with self.assertRaises(ValueError):
            self.save('sign', name='Тестовый разметчик', independent=True)

    def test_frozen_version_is_read_only_and_preserves_originals(self):
        manifest=self.directory.parent/'kt2/manifest.json'
        manifest.parent.mkdir()
        manifest.write_text(json.dumps(dict(status='reviewed_and_frozen')),encoding='utf-8')
        before=self.store.path.read_bytes()
        self.assertTrue(self.store.state()['locked'])
        with self.assertRaisesRegex(ValueError,'зафиксирована'):
            self.save('draft',label=self.valid)
        self.assertEqual(self.store.path.read_bytes(),before)
        self.assertFalse(self.store.draft_path.exists())

    def test_known_answer_needs_at_least_one_fact(self):
        with self.assertRaisesRegex(ValueError, 'хотя бы один факт'):
            self.save('complete', label={**self.valid, 'facts': []})

    def test_unknown_source_and_ambiguous_deletion_cannot_be_completed(self):
        invalid = copy.deepcopy(self.valid)
        invalid['facts'][0]['source_event_ids'] = ['does-not-exist']
        with self.assertRaises(ValueError):
            self.save('complete', label=invalid)
        invalid = {**self.valid, 'deleted_event_ids': ['e1']}
        with self.assertRaises(ValueError):
            self.save('complete', label=invalid)
        self.assertEqual(self.store.state()['form'], self.form)

    def test_stale_tab_does_not_overwrite_newer_work(self):
        old_revision = self.store.revision()
        self.save('draft', label=self.valid)
        with self.assertRaises(ConflictError):
            self.store.mutate(dict(action='draft', revision=old_revision, label=self.blank))
        self.assertEqual(self.store.state()['drafts'][self.valid['case_id']], self.valid)

    def test_page_does_not_expose_gold_or_other_reviewers(self):
        state = self.store.state()
        self.assertNotIn('strata', state)
        self.assertNotIn('expected', json.dumps(state))
        self.assertNotIn('DO NOT READ OTHER FORM', json.dumps(state))

    def test_http_requires_local_host_and_session_token_and_never_serves_files(self):
        server = HTTPServer(('127.0.0.1', 0), make_handler(self.store, 0, 'test-token'))
        port = server.server_address[1]
        server.RequestHandlerClass = make_handler(self.store, port, 'test-token')
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            connection.request('GET', '/api/state')
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
            connection.request('GET', '/api/state', headers={'X-Annotation-Token': 'test-token'})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read())['reviewer'], 'you')
            connection.request('GET', '/eval/annotations/ilya.json')
            response = connection.getresponse()
            self.assertEqual(response.status, 404)
            response.read()
            connection.request('GET', '/', headers={'Host': 'untrusted.example'})
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
            connection.request('POST', '/api/save', body=json.dumps(dict(action='sign')),
                               headers={'X-Annotation-Token': 'test-token', 'Content-Type': 'application/json'})
            response = connection.getresponse()
            self.assertEqual(response.status, 409)
            response.read()
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
