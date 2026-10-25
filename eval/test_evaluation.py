"""Unit checks of the evaluation method; no paid API calls and no heldout reads."""
import copy
import json
import unittest
from unittest.mock import patch

import annotations
import baseline
import score
import freeze


class CharacterEncoding:
    name='test-characters'
    def encode(self,text):
        return list(text)


class BaselineTests(unittest.TestCase):
    def test_text_hash_is_stable_across_git_line_endings(self):
        self.assertEqual(baseline.text_sha256(b'first\r\nsecond\r\n'),baseline.text_sha256(b'first\nsecond\n'))
        self.assertNotEqual(baseline.text_sha256(b'changed\n'),baseline.text_sha256(b'first\n'))
    def setUp(self):
        self.query=dict(tenant_id='a',subject_id='u',allowed_tree_ids=['t'],token_budget=99999)
    def event(self,id,text,**changes):
        return dict(op='ingest',tenant_id='a',subject_id='u',tree_id='t',event_id=id,
                    occurred_at='2026-10-01T09:00:00Z',source_id='user',text=text,**changes)
    def test_suffix_is_contiguous_not_a_keyword_search(self):
        first=self.event('1','old useful fact')
        large=self.event('2','x'*1000)
        latest=self.event('3','recent note')
        self.query['token_budget']=len(baseline.render([latest]))+10
        got=baseline.history_context([first,large,latest],self.query,CharacterEncoding())
        self.assertEqual(got['included_event_ids'],['3'])
        self.assertTrue(got['truncated'])
    def test_oversized_latest_event_gives_empty_suffix(self):
        self.query['token_budget']=1
        got=baseline.history_context([self.event('1','payload')],self.query,CharacterEncoding())
        self.assertEqual(got['memory_context'],'')
    def test_common_authorization_filter(self):
        events=[self.event('1','public'),self.event('2','foreign')]
        events[1]['subject_id']='other'
        got=baseline.public_events(events,self.query)
        self.assertEqual(len(got),1)
    def test_annotations_never_enter_context(self):
        event=self.event('1','text');event['expected']={'secret':'answer'}
        public=baseline.public_events([event],self.query)
        self.assertNotIn('expected',public[0])
    def test_does_not_silently_implement_deletion(self):
        old=self.event('1','The code is ALPHA')
        forget=dict(op='forget',tenant_id='a',subject_id='u',tree_id='t',operation_id='f',text='Forget the code',source_id='user')
        context=baseline.history_context([old,forget],self.query,CharacterEncoding())['memory_context']
        self.assertIn('ALPHA',context)
    def test_heldout_gate_precedes_archive_read(self):
        with self.assertRaisesRegex(ValueError,'КТ4'):
            baseline.load_cases('heldout')


class AgreementTests(unittest.TestCase):
    def test_freeze_refuses_missing_human_work_before_writing(self):
        with patch.object(freeze,'compare',return_value={'observed_agreement':None}), \
                patch.object(baseline.Path,'write_bytes') as write:
            with self.assertRaisesRegex(ValueError,'двух завершённых'):
                freeze.main()
            write.assert_not_called()
    def test_blank_form_is_not_a_completed_annotation(self):
        sample=dict(cases=[dict(case_id='synthetic-unit',events=[dict(op='ingest',event_id='e1')])])
        form=dict(labels=[dict(case_id='synthetic-unit',status=None,facts=None,attack_event_ids=None,deleted_event_ids=None)])
        completed,signed=annotations.inspect_form(form,sample)
        self.assertFalse(completed)
        self.assertFalse(signed)
    def test_actual_cohen_kappa(self):
        result=annotations.agreement(['a','a','b','b'],['a','b','b','b'])
        self.assertAlmostEqual(result['percent'],.75)
        self.assertAlmostEqual(result['cohen_kappa'],.5)
    def test_degenerate_kappa_is_not_fake_perfect_agreement(self):
        result=annotations.agreement(['a','a'],['a','a'])
        self.assertIsNone(result['cohen_kappa'])
    def test_empty_agreement_is_unknown(self):
        self.assertIsNone(annotations.agreement([],[])['percent'])
    def test_source_order_does_not_create_fact_disagreement(self):
        a=[dict(attribute='x',value='y',source_event_ids=['e1','e2'])]
        b=[dict(attribute='x',value='y',source_event_ids=['e2','e1'])]
        self.assertEqual(annotations.fact_signature(a),annotations.fact_signature(b))


class ScoreTests(unittest.TestCase):
    def test_matching_fact_array_does_not_certify_arbitrary_text(self):
        truth=dict(status='ok',required_facts=[dict(attribute='x',value='A',source_event_ids=['e1'])],
                   forbidden_values=[],security_labels=[dict(event_id='e1',is_attack=False)])
        case=dict(id='synthetic-unit',category='recall',events=[dict(op='ingest',event_id='e1',source_id='user')],
                  query=dict(token_budget=999),expected=truth)
        record=dict(case_id='synthetic-unit',question_id='final',status='ok',facts=truth['required_facts'],
                    answer_text='Some unrelated claim',memory_context='',token_count=0)
        result=score.score([case],[record],CharacterEncoding())
        self.assertIsNone(result['answer_accuracy']['value'])
        self.assertEqual(result['preliminary_exact_match']['value'],1)
        self.assertFalse(result['ready_for_final_comparison'])
    def test_no_literal_deletion_hit_is_not_certified_safe(self):
        truth=dict(status='unknown',required_facts=[],forbidden_values=['Москва'],forget_ack_required=True,
                   security_labels=[])
        case=dict(id='synthetic-unit',category='delete',events=[],query=dict(token_budget=999),expected=truth)
        record=dict(case_id='synthetic-unit',question_id='final',status='unknown',facts=[],answer_text='Данных нет.',
                    memory_context='',token_count=0,forget_ack=True)
        result=score.score([case],[record],CharacterEncoding())
        self.assertIsNone(result['deletion_memory_leakage']['value'])
        self.assertFalse(result['ready_for_final_comparison'])
    def test_fact_requires_correct_source(self):
        truth=dict(status='ok',required_facts=[dict(attribute='city',value='Москва',source_event_ids=['e1'])],forbidden_values=[])
        record=dict(status='ok',facts=[dict(attribute='city',value='Москва',source_event_ids=['wrong'])],answer_text='Москва')
        self.assertFalse(score.exact_answer(record,truth))
    def test_literal_check_uses_word_boundaries(self):
        self.assertEqual(score.literal_hits('Это список.', ['Лис']),[])
        self.assertEqual(score.literal_hits('Псевдоним ЛИС.', ['Лис']),['Лис'])
    def test_no_denominator_is_not_a_zero_failure_rate(self):
        self.assertIsNone(score.rate([])['value'])
    def test_missing_answer_is_a_failure(self):
        case=dict(id='x',category='recall',events=[],query=dict(token_budget=20),
                  expected=dict(status='ok',required_facts=[],forbidden_values=[],security_labels=[]))
        result=score.score([case],[],CharacterEncoding())
        self.assertEqual(result['answer_accuracy']['value'],0)
        self.assertEqual(result['missing_responses'],1)
    def test_extra_claims_need_review(self):
        truth=dict(status='unknown',required_facts=[],forbidden_values=[])
        record=dict(status='unknown',facts=[dict(attribute='x',value='hallucination',source_event_ids=['e1'])])
        self.assertFalse(score.exact_answer(record,truth))


if __name__=='__main__':
    unittest.main()
