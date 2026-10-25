# Сервис памяти для агентов

Учебный проект: хранение, поиск, обновление и удаление сведений для чужого агента. В КТ2 подготовлены данные и методика проверки. Сам сервис будем реализовывать в КТ3.

[Описание проекта и КТ2](design_doc.md) — контракт, архитектура, метрики и результаты разметки.

В наборе 100 историй: [70 открытых](eval/kt2/dev.jsonl) и 30 отложенных до КТ4. Илья Чепелюк и Илья Апокорин разметили по 30 историй; расхождения разобраны.

## Проверка на Windows

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r eval/requirements.txt
.venv/Scripts/python.exe -X utf8 eval/check_kt2.py
.venv/Scripts/python.exe -X utf8 eval/validate.py
.venv/Scripts/python.exe -X utf8 -m unittest discover -s eval -p "test_*.py"
.venv/Scripts/python.exe -X utf8 eval/baseline.py
```

Последняя команда собирает усечённую историю без вызова модели. Качество ответов агента пока не измерялось.

Отложенный пакет хранит Илья Чепелюк в `eval/.private/kt2-holdout-v1.zip`. Пакет и личные бланки исключены из Git. Локальная проверка с ними: `python eval/check_kt2.py --require-private`.

`start_annotation.cmd` и `start_annotation_ilya.cmd` открывают исходные бланки для просмотра.
