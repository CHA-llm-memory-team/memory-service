"""Whole-event history truncation. Does not extract facts or call an LLM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import time
import zipfile

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault('TIKTOKEN_CACHE_DIR', str(ROOT / '.cache/tiktoken'))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def text_sha256(data):
    """Git may check text out with CRLF; bind hashes to the same UTF-8/LF content."""
    return sha256(data.replace(b'\r\n', b'\n'))


def load_cases(split='dev', unlock_kt4=False):
    manifest = json.loads((ROOT / 'eval/kt2/manifest.json').read_text(encoding='utf-8'))
    if split == 'heldout':
        if not unlock_kt4:
            raise ValueError('Отложенный набор закрыт до КТ4; обычные команды его не читают.')
        data = (ROOT / manifest['heldout']['path']).read_bytes()
        if sha256(data) != manifest['heldout']['sha256']:
            raise ValueError('Изменилась контрольная сумма отложенного пакета.')
        import io
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            content = archive.read('heldout.jsonl')
    else:
        content = (ROOT / 'eval/kt2/dev.jsonl').read_bytes()
        digest=text_sha256(content) if manifest.get('text_hash_normalization')=='lf' else sha256(content)
        if digest != manifest['development']['sha256']:
            raise ValueError('Изменилась контрольная сумма видимого набора; нужна новая версия.')
    return [json.loads(line) for line in content.decode('utf-8').splitlines() if line.strip()]


def questions(case):
    for i, point in enumerate(case.get('checkpoints', [])):
        yield f'checkpoint-{i + 1}', point['after_event_count'], point['query'], point['expected']
    yield 'final', len(case['events']), case['query'], case['expected']


def public_events(events, query):
    """Common authorization gate; no semantic forgetting/TTL/revision policy."""
    keys = ('op', 'tree_id', 'event_id', 'operation_id', 'occurred_at', 'source_id', 'text', 'valid_until')
    return [{k: e[k] for k in keys if k in e} for e in events
            if e['op'] in ('ingest', 'forget')
            and e['tenant_id'] == query['tenant_id']
            and e['subject_id'] == query['subject_id']
            and e['tree_id'] in query['allowed_tree_ids']]


def render(events):
    return '\n'.join(json.dumps(e, ensure_ascii=False, sort_keys=True, separators=(',', ':')) for e in events)


def history_context(events, query, encoding):
    permitted = public_events(events, query)
    selected = []
    for event in reversed(permitted):
        candidate = [event] + selected
        if len(encoding.encode(render(candidate))) > query['token_budget']:
            break  # Contiguous suffix; never jump over a long recent event.
        selected = candidate
    context = render(selected)
    return dict(memory_context=context, token_count=len(encoding.encode(context)),
                included_event_ids=[e.get('event_id', e.get('operation_id')) for e in selected],
                truncated=len(selected) != len(permitted), available_events=len(permitted),
                included_events=len(selected))


def make_records(cases, encoding):
    for case in cases:
        for qid, count, query, _ in questions(case):
            start = time.perf_counter()
            context = history_context(case['events'][:count], query, encoding)
            yield dict(case_id=case['id'], question_id=qid, query=query,
                       **context, baseline='whole-event-suffix-v1', encoding=encoding.name,
                       preparation_ms=(time.perf_counter() - start) * 1000)


def main():
    parser = argparse.ArgumentParser(description='Усечь историю без обращения к языковой модели.')
    parser.add_argument('--split', choices=['dev', 'heldout'], default='dev')
    parser.add_argument('--unlock-kt4', action='store_true')
    parser.add_argument('--output', type=Path, default=ROOT / 'eval/runs/history-dev.jsonl')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    cases = load_cases(args.split, args.unlock_kt4)
    import tiktoken
    encoding = tiktoken.get_encoding('o200k_base')
    records = list(make_records(cases, encoding))
    manifest=json.loads((ROOT/'eval/kt2/manifest.json').read_text(encoding='utf-8'))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in records), encoding='utf-8')
    summary = dict(kind='context_preparation_only', split=args.split, cases=len(cases), questions=len(records),
                   dataset_version=manifest['version'],
                   dataset_sha256=manifest['development' if args.split=='dev' else 'heldout']['sha256'],
                   encoding=encoding.name, contexts_over_budget=sum(r['token_count'] > r['query']['token_budget'] for r in records),
                   truncated_contexts=sum(r['truncated'] for r in records),
                   mean_memory_tokens=round(statistics.mean(r['token_count'] for r in records), 2),
                   paid_model_calls=0, answer_quality=None,
                   notes='Проверена подготовка контекста; ответы агента и качество памяти не измерялись.')
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
