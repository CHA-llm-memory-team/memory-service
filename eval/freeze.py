"""Freeze only after two real forms and confirmed human resolution exist."""
import copy
import hashlib
import json

from annotations import DIR, compare, resolution_complete
from baseline import ROOT, load_cases, text_sha256
from validate import check_case


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    agreement=compare()
    if agreement['observed_agreement'] is None:
        raise ValueError('Фиксация невозможна: нет двух завершённых независимых человеческих разметок.')
    sample=json.loads((DIR/'sample.json').read_text(encoding='utf-8'))
    resolution=DIR/'adjudicated.json'
    if not resolution_complete(resolution,sample):
        raise ValueError('Фиксация невозможна: разбор и подтверждение 30 историй не завершены.')
    cases=copy.deepcopy(load_cases())
    by_id={c['id']:c for c in cases}
    resolution_document=json.loads(resolution.read_text(encoding='utf-8'))
    rows=resolution_document['cases']
    originals={name:json.loads((DIR/f'{name}.json').read_text(encoding='utf-8'))
               for name in ('you','ilya')}
    original_labels={name:{r['case_id']:r for r in form['labels']}
                     for name,form in originals.items()}
    for row in rows:
        if (row['reviewer_a']!=original_labels['you'][row['case_id']]
                or row['reviewer_b']!=original_labels['ilya'][row['case_id']]):
            raise ValueError('Исходная разметка изменилась после начала разбора.')
    for row in rows:
        case=by_id[row['case_id']]
        labels=row['resolved_labels']
        expected=case['expected']
        events={e['event_id']:e for e in case['events'] if e['op']=='ingest'}
        facts=[]
        for original in labels['facts']:
            fact=copy.deepcopy(original)
            if not fact['source_event_ids']:
                raise ValueError('У согласованного факта отсутствует источник.')
            trees={events[eid]['tree_id'] for eid in fact['source_event_ids']}
            if len(trees)!=1:
                raise ValueError('Для нескольких деревьев разметьте факты отдельно, не теряя их происхождение.')
            fact['tree_id']=next(iter(trees))
            facts.append(fact)
        expected.update(status=labels['status'],required_facts=facts,
            security_labels=[dict(event_id=eid,is_attack=eid in labels['attack_event_ids']) for eid in events],
            forget_target_event_ids=labels['deleted_event_ids'])
        expected.pop('alternative_source_event_ids',None)
        expected['required_security_events']=[dict(event_id=eid,kind='suspected_memory_poisoning',
                                                  source_required=True,reason_required=True)
                                              for eid in events if eid in labels['attack_event_ids']]
        if 'forbidden_values' in labels:
            expected['forbidden_values']=labels['forbidden_values']
        if case['category']=='delete':
            expected['forget_ack_required']=labels['status']!='needs_clarification'
        expected['human_review']=dict(confirmed_by=row['confirmed_by'],reason=row['reason'],
                                      scope='final_answer_security_and_forget_targets')
    policy=json.loads((ROOT/'eval/source_policy.json').read_text(encoding='utf-8'))
    for case in cases:check_case(case,policy)
    folder=ROOT/'eval/kt2'
    manifest=json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
    if manifest['status']=='reviewed_and_frozen':
        raise ValueError('Версия уже зафиксирована. Новые изменения требуют новой версии, а не повторной фиксации.')
    # Never opens the heldout archive; only bind its existing digest to this revision.
    archive=ROOT/manifest['heldout']['path']
    if sha(archive.read_bytes())!=manifest['heldout']['sha256']:
        raise ValueError('Изменился отложенный пакет.')
    data=('\n'.join(json.dumps(c,ensure_ascii=False,separators=(',',':')) for c in cases)+'\n').encode()
    previous=manifest['development']['sha256']
    protocol=json.loads((folder/'protocol.json').read_text(encoding='utf-8'))
    protocol['status']='reviewed_and_frozen'
    protocol['annotation']['observed_agreement']=agreement['observed_agreement']
    protocol['release_gates']['human_annotations_complete']=True
    protocol['release_gates']['disagreements_resolved']=True
    public_review=dict(version='kt2-annotation-review-v1',
        reviewers={name:dict(completed_by=form['completed_by'],completed_at=form['completed_at'],
                            independently_completed=form['independently_completed'])
                   for name,form in originals.items()},
        agreement_before_resolution=agreement['observed_agreement'],
        assistance_log=protocol['annotation'].get('assistance_log',[]),
        confirmed_at=resolution_document.get('confirmed_at'),
        resolution_authority=resolution_document.get('resolution_authority',{}),
        cases=rows)
    review_bytes=(json.dumps(public_review,ensure_ascii=False,indent=2)+'\n').encode()
    review_path=folder/'annotation_resolution.json'
    manifest.update(version='kt2-v1-reviewed',status='reviewed_and_frozen',
                    text_hash_normalization='lf',
                    human_reviewed_final_cases=len(rows),
                    human_evidence={name:sha((DIR/name).read_bytes()) for name in ('you.json','ilya.json','adjudicated.json')})
    manifest['annotation_review']=dict(path='eval/kt2/annotation_resolution.json',
                                      sha256=text_sha256(review_bytes),count=len(rows))
    manifest['source_policy_sha256']=text_sha256((ROOT/'eval/source_policy.json').read_bytes())
    manifest['development']['previous_candidate_sha256']=previous
    manifest['development']['sha256']=text_sha256(data)
    protocol_bytes=(json.dumps(protocol,ensure_ascii=False,indent=2)+'\n').encode()
    manifest['method_hashes']={path.relative_to(ROOT).as_posix():text_sha256(path.read_bytes()) for path in
        (ROOT/'eval/baseline.py',ROOT/'eval/score.py',ROOT/'eval/annotations.py',
         ROOT/'eval/freeze.py',ROOT/'eval/validate.py',ROOT/'eval/check_kt2.py',
         ROOT/'eval/kt2/answer_instructions.txt',ROOT/'design_doc.md')}
    manifest['method_hashes']['eval/kt2/protocol.json']=text_sha256(protocol_bytes)
    # All preconditions and validations finish before the first write.
    (folder/'dev.jsonl').write_bytes(data)
    (folder/'protocol.json').write_bytes(protocol_bytes)
    review_path.write_bytes(review_bytes)
    (folder/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    (DIR/'agreement.json').write_text(json.dumps(agreement,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    from status import main as update_status
    update_status()
    print(f'Зафиксирована просмотренная версия: {len(rows)} конечных ответов прошли разбор; остальные эталоны остаются авторскими. КТ4-пакет не открыт.')


if __name__=='__main__':
    main()
