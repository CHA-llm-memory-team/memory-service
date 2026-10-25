"""Report actual KT2 readiness; missing human decisions remain missing."""
import json
from pathlib import Path

from baseline import ROOT
from annotations import DIR, compare, resolution_complete


def main():
    annotation=compare()
    sample=json.loads((DIR/'sample.json').read_text(encoding='utf-8'))
    resolved=resolution_complete(DIR/'adjudicated.json',sample)
    manifest=json.loads((ROOT/'eval/kt2/manifest.json').read_text(encoding='utf-8'))
    if annotation['observed_agreement'] is None:
        next_action='Завершить обе разметки и подтверждения самостоятельной работы.'
    elif not resolved:
        next_action='Совместно разобрать расхождения и подтвердить решения в adjudicated.json.'
    elif manifest['status']!='reviewed_and_frozen':
        next_action='Зафиксировать подтверждённую версию командой python eval/freeze.py.'
    else:
        next_action='КТ2 зафиксирована; следующий этап — общий запуск и сравнение для КТ3.'
    report=dict(base_commit=manifest['base_commit'],branch='kt2-evaluation',
        candidate_histories=100,development=70,heldout=30,heldout_keeper='you',
        heldout_handling='ordinary_commands_check_hash_without_opening_contents',
        human_annotations=annotation,disagreements_adjudicated=bool(resolved),
        ready_to_freeze=annotation['observed_agreement'] is not None and bool(resolved)
                        and manifest['status']!='reviewed_and_frozen',
        ready_for_kt2=annotation['observed_agreement'] is not None and bool(resolved)
                      and manifest['status']=='reviewed_and_frozen',
        actual_agent_comparison_run=False,
        next_action=next_action)
    path=ROOT/'eval/kt2/status.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False,indent=2))


if __name__=='__main__':
    main()
