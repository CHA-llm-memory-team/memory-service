"""Local human annotation UI. Reads only public inputs and the chosen person's form."""
import argparse
from datetime import datetime
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import secrets
import tempfile
from urllib.request import urlopen
import webbrowser

from annotations import DIR, inspect_form


class ConflictError(ValueError):
    pass


def atomic_write(path, value):
    data = json.dumps(value, ensure_ascii=False, indent=2) + '\n'
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=path.parent,
                                     delete=False, suffix='.tmp') as stream:
        temporary = Path(stream.name)
        stream.write(data)
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


class AnnotationStore:
    def __init__(self, directory, reviewer):
        self.directory = Path(directory)
        self.reviewer = reviewer
        self.path = self.directory / f'{reviewer}.json'
        self.draft_path = self.directory / f'{reviewer}.draft.json'
        self.manifest_path = self.directory.parent / 'kt2/manifest.json'
        self.sample = json.loads((self.directory / 'sample.json').read_text(encoding='utf-8'))
        self.cases = {c['case_id']: c for c in self.sample['cases']}
        self.backed_up = False
        if not self.path.exists():
            raise ValueError('Бланк отсутствует. Сначала выполните python eval/annotations.py init.')
        self.read()

    def read(self):
        form = json.loads(self.path.read_text(encoding='utf-8'))
        if form['reviewer_id'] != self.reviewer:
            raise ValueError('В бланке указан другой участник.')
        inspect_form(form, self.sample)
        drafts = json.loads(self.draft_path.read_text(encoding='utf-8')) if self.draft_path.exists() else {}
        return form, drafts

    def revision(self):
        content = self.path.read_bytes() + b'\0'
        if self.draft_path.exists():
            content += self.draft_path.read_bytes()
        return hashlib.sha256(content).hexdigest()

    def is_locked(self):
        return (self.manifest_path.exists() and
                json.loads(self.manifest_path.read_text(encoding='utf-8')).get('status')=='reviewed_and_frozen')

    def state(self):
        form, drafts = self.read()
        completed, signed = inspect_form(form, self.sample)
        # Do not send category strata, gold answers, agreement, or the other person's form.
        return dict(reviewer=self.reviewer, revision=self.revision(), form=form, drafts=drafts,
                    cases=[self.cases[row['case_id']] for row in form['labels']],
                    completed=list(completed), signed=signed, locked=self.is_locked())

    def mutate(self, payload):
        if self.is_locked():
            raise ValueError('КТ2 уже зафиксирована. Исходные разметки доступны только для просмотра; изменения требуют новой версии.')
        if payload.get('revision') != self.revision():
            raise ConflictError('Бланк изменён в другой вкладке или программе. Обновите страницу перед продолжением.')
        form, drafts = self.read()
        action = payload.get('action')
        if action == 'sign':
            completed, _ = inspect_form(form, self.sample)
            if len(completed) != len(self.cases) or drafts:
                raise ValueError('Сначала завершите все истории, включая сохранённые черновики.')
            name = payload.get('name', '')
            if not isinstance(name, str) or not name.strip() or payload.get('independent') is not True:
                raise ValueError('Укажите имя и подтвердите самостоятельную работу.')
            form.update(completed_by=name.strip(), completed_at=datetime.now().astimezone().isoformat(),
                        independently_completed=True)
            self.save_form(form)
        elif action in ('draft', 'complete'):
            row = payload.get('label')
            if not isinstance(row, dict) or row.get('case_id') not in self.cases:
                raise ValueError('Неизвестная история.')
            case_id = row['case_id']
            if set(row) != {'case_id', 'status', 'facts', 'attack_event_ids', 'deleted_event_ids', 'notes'}:
                raise ValueError('Неверные поля разметки.')
            if not isinstance(row['notes'], str) or len(json.dumps(row)) > 200000:
                raise ValueError('Неверный формат или слишком длинный ответ.')
            if action == 'complete':
                self.validate_complete(row)
                form['labels'] = [row if old['case_id'] == case_id else old for old in form['labels']]
                drafts.pop(case_id, None)
            else:
                drafts[case_id] = row
            # Any edit revokes an earlier final signature; it must be confirmed again.
            form.update(completed_by=None, completed_at=None, independently_completed=None)
            self.save_form(form)
            atomic_write(self.draft_path, drafts)
        else:
            raise ValueError('Неизвестная команда.')
        return self.state()

    def validate_complete(self, row):
        if not isinstance(row.get('facts'), list):
            raise ValueError('Проверьте список фактов.')
        if row.get('status') == 'ok' and not row['facts']:
            raise ValueError('Ответ известен: добавьте хотя бы один факт для ответа.')
        for fact in row['facts']:
            if not isinstance(fact, dict) or not isinstance(fact.get('attribute'), str) or not fact['attribute'].strip():
                raise ValueError('У каждого факта должно быть название свойства.')
            if 'value' not in fact or fact['value'] is None or fact['value'] == '':
                raise ValueError('У каждого факта должно быть значение.')
            if not isinstance(fact.get('source_event_ids'), list) or not fact['source_event_ids']:
                raise ValueError('Укажите хотя бы одно событие-источник для каждого факта.')
        sample = {'cases': [self.cases[row['case_id']]]}
        try:
            completed, _ = inspect_form({'labels': [row]}, sample)
        except (ValueError, TypeError, KeyError) as error:
            raise ValueError(f'Проверьте ответ: {error}') from error
        if not completed:
            raise ValueError('Выберите статус ответа.')

    def save_form(self, form):
        if not self.backed_up:
            stamp = datetime.now().strftime('%Y%m%d-%H%M%S-%f')
            backup = self.directory / f'{self.reviewer}.{stamp}.backup.json'
            backup.write_bytes(self.path.read_bytes())
            self.backed_up = True
        atomic_write(self.path, form)


def make_handler(store, port, token):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def send(self, status, data, kind='application/json; charset=utf-8'):
            body = data.encode('utf-8') if isinstance(data, str) else json.dumps(data, ensure_ascii=False).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; connect-src 'self'")
            self.end_headers()
            self.wfile.write(body)

        def authorized(self, api=False):
            if self.headers.get('Host') not in (f'127.0.0.1:{port}', f'localhost:{port}'):
                self.send(403, {'error': 'Используйте адрес локального сервера.'})
                return False
            if api and self.headers.get('X-Annotation-Token') != token:
                self.send(403, {'error': 'Обновите страницу.'})
                return False
            return True

        def do_GET(self):
            if not self.authorized(self.path.startswith('/api/')):
                return
            if self.path == '/':
                html = Path(__file__).with_name('annotation_ui.html').read_text(encoding='utf-8')
                self.send(200, html.replace('__SESSION_TOKEN__', token), 'text/html; charset=utf-8')
            elif self.path == '/api/state':
                self.send(200, store.state())
            elif self.path == '/api/export':
                self.send(200, store.read()[0])
            elif self.path == '/health':
                self.send(200, dict(application='memory-annotation', reviewer=store.reviewer))
            else:
                self.send(404, {'error': 'Страница не найдена.'})

        def do_POST(self):
            if not self.authorized(True):
                return
            if self.path != '/api/save':
                self.send(404, {'error': 'Команда не найдена.'})
                return
            try:
                length = int(self.headers.get('Content-Length', 0))
                if not 0 < length <= 500000:
                    raise ValueError('Неверный размер запроса.')
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError('Неверный запрос.')
                self.send(200, store.mutate(payload))
            except ConflictError as error:
                self.send(409, {'error': str(error)})
            except (ValueError, TypeError, KeyError) as error:
                self.send(400, {'error': str(error)})
    return Handler


def main():
    parser = argparse.ArgumentParser(description='Локальная страница независимой разметки КТ2.')
    parser.add_argument('--reviewer', choices=('you', 'ilya'), default='you')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--open', action='store_true', help='Открыть в браузере')
    args = parser.parse_args()
    store = AnnotationStore(DIR, args.reviewer)
    token = secrets.token_urlsafe(32)
    url = f'http://127.0.0.1:{args.port}/'
    try:
        server = HTTPServer(('127.0.0.1', args.port), make_handler(store, args.port, token))
    except OSError as error:
        if args.open:
            try:
                with urlopen(url + 'health', timeout=2) as response:
                    existing = json.load(response)
                if existing == dict(application='memory-annotation', reviewer=args.reviewer):
                    webbrowser.open(url)
                    print(f'Страница уже запущена: {url}')
                    return
            except (OSError, ValueError):
                pass
        raise SystemExit(f'Не удалось занять порт {args.port}. Укажите другой: --port 8766. ({error})')
    print(f'Разметка {args.reviewer}: {url}\nОстановка: Ctrl+C. Ответы сохраняются в {store.path}', flush=True)
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
