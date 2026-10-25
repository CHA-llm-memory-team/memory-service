"""Independent human annotation forms and agreement. Never fills labels from gold."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import unicodedata

from baseline import ROOT, load_cases

DIR = ROOT / 'eval/annotations'
STATUSES = {'ok', 'unknown', 'conflict', 'needs_clarification'}
SAMPLE_COUNTS = dict(recall=3, update=3, conflict=3, delete=6, expiry=3,
                     poisoning=6, security_control=4, noise=2)


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def initialize():
    cases = load_cases()
    rng = random.Random(20261025)
    selected = []
    for category, size in SAMPLE_COUNTS.items():
        candidates = [c for c in cases if c['category'] == category and c['id'].startswith('kt2-dev-')]
        rng.shuffle(candidates)
        if len(candidates) < size:
            raise ValueError(f'Недостаточно новых историй категории {category}')
        selected.extend(candidates[:size])
    sample = dict(version='kt2-annotation-v1', count=len(selected), strata=SAMPLE_COUNTS,
                  cases=[dict(case_id=c['id'], events=c['events'], query=c['query']) for c in selected])
    sample_path = DIR / 'sample.json'
    if sample_path.exists() and json.loads(sample_path.read_text(encoding='utf-8')) != sample:
        raise ValueError('Существующая подвыборка отличается; не перезаписываем выполненную работу.')
    write(sample_path, sample)
    for index, reviewer in enumerate(('you', 'ilya')):
        ids = [c['id'] for c in selected]
        random.Random(720 + index).shuffle(ids)
        form = dict(version='kt2-annotation-v1', reviewer_id=reviewer, completed_by=None,
                    completed_at=None, independently_completed=None, input_file='sample.json',
                    labels=[dict(case_id=i, status=None, facts=None, attack_event_ids=None,
                                 deleted_event_ids=None, notes='') for i in ids])
        path = DIR / f'{reviewer}.json'
        if not path.exists():
            write(path, form)
    print('Созданы 30 входных историй без expected и два незаполненных бланка: you.json, ilya.json.')


def normalized(value):
    if isinstance(value, str):
        return ' '.join(unicodedata.normalize('NFKC', value).casefold().split())
    if isinstance(value, list):
        return [normalized(v) for v in value]
    if isinstance(value, dict):
        return {k: normalized(v) for k, v in value.items()}
    return value


def fact_signature(facts):
    # Exact normalized agreement is a lower bound; adjudication handles paraphrases.
    return sorted(json.dumps(normalized({**f,'source_event_ids':sorted(f['source_event_ids'])}),
                             ensure_ascii=False, sort_keys=True) for f in facts)


def agreement(a, b):
    if not a:
        return dict(n=0, percent=None, cohen_kappa=None)
    observed = sum(x == y for x, y in zip(a, b)) / len(a)
    ca, cb = Counter(a), Counter(b)
    chance = sum(ca[k] * cb[k] for k in ca.keys() | cb.keys()) / len(a) ** 2
    return dict(n=len(a), percent=observed, cohen_kappa=(observed-chance)/(1-chance) if chance < 1 else None)


def inspect_form(form, sample):
    entries = form['labels']
    inputs = {c['case_id']: c for c in sample['cases']}
    if len(entries) != len(inputs) or {c['case_id'] for c in entries} != set(inputs):
        raise ValueError('Набор идентификаторов бланка не совпадает с подвыборкой.')
    completed = {}
    for label in entries:
        fields = ('status', 'facts', 'attack_event_ids', 'deleted_event_ids')
        if any(label.get(k) is None for k in fields):
            continue
        if label['status'] not in STATUSES or not all(isinstance(label[k], list) for k in fields[1:]):
            raise ValueError(f"Неверный формат меток: {label['case_id']}")
        if label['status']=='unknown' and label['facts']:
            raise ValueError('При status=unknown список facts должен быть пустым.')
        if label['deleted_event_ids'] and (label['status']=='needs_clarification'
                or not any(e['op']=='forget' for e in inputs[label['case_id']]['events'])):
            raise ValueError('Удаление не произошло: нет однозначной отдельной команды forget.')
        ids = {e['event_id'] for e in inputs[label['case_id']]['events'] if e['op'] == 'ingest'}
        if not set(label['attack_event_ids']) <= ids or not set(label['deleted_event_ids']) <= ids:
            raise ValueError(f"Метка ссылается на неизвестное событие: {label['case_id']}")
        for fact in label['facts']:
            if not isinstance(fact,dict) or not {'attribute', 'value', 'source_event_ids'} <= fact.keys() \
                    or not fact['source_event_ids'] or not set(fact['source_event_ids']) <= ids:
                raise ValueError('Факт должен содержать смысловой атрибут, значение и существующие источники.')
        completed[label['case_id']] = label
    signed = bool(form.get('completed_by') and form.get('completed_at')
                  and form.get('independently_completed') is True)
    return completed, signed


def compare():
    sample = json.loads((DIR / 'sample.json').read_text(encoding='utf-8'))
    forms = [json.loads((DIR / f'{name}.json').read_text(encoding='utf-8')) for name in ('you', 'ilya')]
    inspected = [inspect_form(f, sample) for f in forms]
    report = dict(status='awaiting_two_human_annotations', sample_size=sample['count'],
                  completed={f['reviewer_id']:len(p[0]) for f,p in zip(forms,inspected)},
                  independent_attestations={f['reviewer_id']:p[1] for f,p in zip(forms,inspected)},
                  observed_agreement=None)
    if not all(len(labels) == sample['count'] and signed for labels,signed in inspected):
        return report
    a,b = inspected[0][0],inspected[1][0]
    ids = [c['case_id'] for c in sample['cases']]
    attacks_a,attacks_b=[],[]
    for row in sample['cases']:
        key=row['case_id']
        for event in dict.fromkeys(e['event_id'] for e in row['events'] if e['op']=='ingest'):
            attacks_a.append(event in a[key]['attack_event_ids'])
            attacks_b.append(event in b[key]['attack_event_ids'])
    report.update(status='human_annotations_complete',
        observed_agreement=dict(status=agreement([a[i]['status'] for i in ids],[b[i]['status'] for i in ids]),
            attack_events=agreement(attacks_a,attacks_b),
            fact_set_exact_agreement=sum(fact_signature(a[i]['facts'])==fact_signature(b[i]['facts']) for i in ids)/len(ids),
            forget_target_set_exact_agreement=sum(set(a[i]['deleted_event_ids'])==set(b[i]['deleted_event_ids']) for i in ids)/len(ids)),
        disagreement_case_ids=[i for i in ids if a[i]['status']!=b[i]['status']
            or fact_signature(a[i]['facts'])!=fact_signature(b[i]['facts'])
            or set(a[i]['attack_event_ids'])!=set(b[i]['attack_event_ids'])
            or set(a[i]['deleted_event_ids'])!=set(b[i]['deleted_event_ids'])])
    return report


def resolution_complete(path, sample):
    if not path.exists():
        return False
    rows=json.loads(path.read_text(encoding='utf-8')).get('cases',[])
    if len(rows)!=sample['count'] or not all(row.get('resolved_labels') is not None
                                            and row.get('confirmed_by') and row.get('reason') for row in rows):
        return False
    labels=[{**row['resolved_labels'],'case_id':row['case_id']} for row in rows]
    inspected,_=inspect_form({'labels':labels},sample)
    return len(inspected)==sample['count']


def main():
    parser=argparse.ArgumentParser(description='Бланки разметки и фактическое согласие двух людей.')
    parser.add_argument('command',choices=['init','compare','show','adjudicate'])
    parser.add_argument('--case')
    parser.add_argument('--output',type=Path,default=DIR/'agreement.json')
    args=parser.parse_args()
    if args.command=='init':
        initialize()
    elif args.command=='show':
        sample=json.loads((DIR/'sample.json').read_text(encoding='utf-8'))
        found=[c for c in sample['cases'] if c['case_id']==args.case]
        if not found:raise ValueError('Укажите --case из своего бланка.')
        print(json.dumps(found[0],ensure_ascii=False,indent=2))
    elif args.command=='adjudicate':
        report=compare()
        if report['observed_agreement'] is None:
            raise ValueError('Сначала нужны два полностью заполненных независимых бланка.')
        path=DIR/'adjudicated.json'
        if path.exists():
            raise ValueError('Файл разбора уже существует; не перезаписываем решения людей.')
        forms=[json.loads((DIR/f'{name}.json').read_text(encoding='utf-8')) for name in ('you','ilya')]
        maps=[{x['case_id']:x for x in f['labels']} for f in forms]
        rows=[dict(case_id=i,reviewer_a=maps[0][i],reviewer_b=maps[1][i],
                   resolved_labels=None,confirmed_by=None,reason='') for i in maps[0]]
        write(path,dict(status='requires_human_resolution',cases=rows))
        print('Создан adjudicated.json. Решения и подтверждение заполняет человек; эталон автоматически не меняется.')
    else:
        report=compare();write(args.output,report)
        print(json.dumps(report,ensure_ascii=False,indent=2))
        if report['observed_agreement'] is None:raise SystemExit(2)


if __name__=='__main__':
    main()
