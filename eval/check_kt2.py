"""Validate published KT2 data; optionally require the keeper's private artifacts."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from baseline import ROOT, load_cases, questions, text_sha256
from annotations import inspect_form, agreement, fact_signature
from validate import check_case, require


def main():
    parser=argparse.ArgumentParser(description='Проверить КТ2 без открытия отложенных историй.')
    parser.add_argument('--require-private',action='store_true',help='Потребовать локальный пакет и исходные личные бланки')
    args=parser.parse_args()
    folder=ROOT/'eval/kt2'
    manifest=json.loads((folder/'manifest.json').read_text(encoding='utf-8'))
    digest=text_sha256 if manifest.get('text_hash_normalization')=='lf' else lambda data:hashlib.sha256(data).hexdigest()
    policy=json.loads((ROOT/'eval/source_policy.json').read_text(encoding='utf-8'))
    cases=load_cases()
    require(len(cases)==70 and len({c['id'] for c in cases})==70,'Expected 70 development cases')
    require(Counter(c['category'] for c in cases)==manifest['development']['categories'],'Category manifest mismatch')
    families=[c['family_id'] for c in cases]
    require(len(families)==len(set(families)),'Repeated development family')
    published=[json.loads(x) for x in (ROOT/'eval/kt1_examples.jsonl').read_text(encoding='utf-8').splitlines()]
    for old,new in zip(published,cases[:20]):
        without_provenance={k:v for k,v in new.items() if k not in ('family_id','lineage')}
        require(old==without_provenance,'Published KT1 cases changed silently')
    for case in cases:check_case(case,policy)
    require(digest((ROOT/'eval/source_policy.json').read_bytes())==manifest['source_policy_sha256'],
            'Source policy changed without a dataset version change')
    held_path=ROOT/manifest['heldout']['path']
    if args.require_private:
        require(held_path.exists(),'Keeper archive is missing locally')
    if held_path.exists():
        require(hashlib.sha256(held_path.read_bytes()).hexdigest()==manifest['heldout']['sha256'],'Keeper archive hash mismatch')
    require(manifest['heldout']['count']==30 and manifest['total_cases']==100,'Incorrect split sizes')
    sample=json.loads((ROOT/'eval/annotations/sample.json').read_text(encoding='utf-8'))
    require(len(sample['cases'])==30 and len({x['case_id'] for x in sample['cases']})==30,'Invalid annotation sample')
    dev_by_id={c['id']:c for c in cases}
    for item in sample['cases']:
        require(set(item)=={'case_id','events','query'},'Gold labels leaked into annotation input')
        case=dev_by_id[item['case_id']]
        require(item['events']==case['events'] and item['query']==case['query'],'Annotation input mismatch')
    if manifest['status']=='reviewed_and_frozen':
        for relative,expected_digest in manifest['method_hashes'].items():
            require((text_sha256((ROOT/relative).read_bytes()) if manifest.get('text_hash_normalization')=='lf'
                     else hashlib.sha256((ROOT/relative).read_bytes()).hexdigest())==expected_digest,
                    f'Frozen method changed: {relative}')
        review_meta=manifest['annotation_review']
        raw=(ROOT/review_meta['path']).read_bytes()
        require((text_sha256(raw) if manifest.get('text_hash_normalization')=='lf' else hashlib.sha256(raw).hexdigest())
                ==review_meta['sha256'],'Public annotation review changed')
        review=json.loads(raw)
        rows=review['cases']
        require(len(rows)==30 and {r['case_id'] for r in rows}=={c['case_id'] for c in sample['cases']},
                'Incomplete public annotation review')
        before=review['agreement_before_resolution']
        require(agreement([r['reviewer_a']['status'] for r in rows],[r['reviewer_b']['status'] for r in rows])==before['status'],
                'Status agreement is not reproducible from original forms')
        attack_a,attack_b=[],[]
        for row in rows:
            case_id=row['case_id']
            require(row['confirmed_by'] and row['reason'],'Unconfirmed final annotation')
            for key in ('reviewer_a','reviewer_b','resolved_labels'):
                label={**row[key],'case_id':case_id}
                done,_=inspect_form({'labels':[label]}, {'cases':[dev_by_id[case_id]|{'case_id':case_id}]})
                require(len(done)==1,'Incomplete annotation in public review')
            final=dev_by_id[case_id]['expected']
            label=row['resolved_labels']
            require(final['status']==label['status'],'Final status differs from confirmed review')
            facts=[{k:v for k,v in f.items() if k!='tree_id'} for f in final['required_facts']]
            require(fact_signature(facts)==fact_signature(label['facts']),'Final facts differ from confirmed review')
            require(set(final['forget_target_event_ids'])==set(label['deleted_event_ids']),'Final deletion targets differ')
            require({x['event_id'] for x in final['security_labels'] if x['is_attack']}==set(label['attack_event_ids']),
                    'Final attack labels differ')
            for eid in {e['event_id'] for e in dev_by_id[case_id]['events'] if e['op']=='ingest'}:
                attack_a.append(eid in row['reviewer_a']['attack_event_ids'])
                attack_b.append(eid in row['reviewer_b']['attack_event_ids'])
        require(agreement(attack_a,attack_b)==before['attack_events'],'Attack agreement is not reproducible')
        require(sum(fact_signature(r['reviewer_a']['facts'])==fact_signature(r['reviewer_b']['facts']) for r in rows)/len(rows)
                ==before['fact_set_exact_agreement'],'Original fact agreement changed')
        require(sum(set(r['reviewer_a']['deleted_event_ids'])==set(r['reviewer_b']['deleted_event_ids']) for r in rows)/len(rows)
                ==before['forget_target_set_exact_agreement'],'Original deletion agreement changed')
        for name,digest in manifest['human_evidence'].items():
            path=ROOT/'eval/annotations'/name
            if args.require_private:require(path.exists(),f'Private evidence is missing: {name}')
            if path.exists():require(hashlib.sha256(path.read_bytes()).hexdigest()==digest,f'Private evidence changed: {name}')
    print(f"OK: 70 development stories, {sum(1 for c in cases for _ in questions(c))} questions, "
          '30 annotation inputs; published review and method hashes checked when frozen. '
          +('Keeper archive checksum checked.' if held_path.exists() else 'Keeper archive absent here; public checks only.')
          +' Heldout contents were not opened.')


if __name__=='__main__':
    main()
