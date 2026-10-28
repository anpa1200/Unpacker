# Sol 6.1, ускорение эмуляции и проверка корпуса — 22 октября 2026

Локальный этап разработки `/path/to/Unpacker`, `origin`
`anpa1200/Unpacker`, ветка `main`, HEAD
`29dd691bd339ead5e6bd080a976e2ee2f12c3d63`. Предыдущие незакоммиченные изменения
сохранены. Этот документ фиксирует новый этап и не переписывает исторические отчёты.
Коммит, push, публикация и удалённый CI не выполнялись.

## Проверенный результат

* 402 автоматических теста, включая 95 AI-тестов, прошли без skip/failure/error.
  Перед этим этапом было 367 тестов, включая шесть тестов выбора Sol 6.1.
* Последовательный прогон всех 54 существующих файлов на окончательном snapshot:
  **33 извлечённых, 7 частичных, 14 невосстановленных**.
  Точные статусы: `{"extracted": 30, "extracted_vendor_format": 3, "failed": 7, "partial": 7, "timeout": 3, "unsupported": 4}`.
  Продолжительность прогона 473.12 с.
* Сравнение с предыдущим полным прогоном 33/7/14: потерянных ранее пройденных
  gate — **0**. Все различия результата/ошибки записаны в
  `comparison-402.json`; ниже приведены все 54 строки, включая неудачи.
* Предел decode 60 с, общий предел задания 75 с, output quota 32 MiB сохранены.
  Образцы выполнялись только гостевым эмулятором внутри production Bubblewrap
  sandbox без сети. Нативный запуск образцов не проводился.
* 85 проверок SHA-256 входов и оригиналов подтвердили соответствие исходному
  манифесту. Образцы, оригиналы и критерии сравнения не изменялись.

Корпус содержит 54 файла, 31 пару с оригиналом, только 12 различных хешей
оригиналов и 33 исходные метки семейства (32 после нормализации регистра).
Преобладание вариантов UPX ограничивает репрезентативность. Семейства передавались
как явный выбор backend: это не оценка полноты автоматического детектора.

## Реализованные изменения

### Ограниченный инкрементальный учёт записей

`src/unpacker/write_ranges.py`: `WriteRangeTracker` поддерживает отсортированное
объединение интервалов с двоичным поиском. Запись внутрь уже покрытого интервала
не сортирует весь список и не создаёт новый. Сохранена включительная конвенция
границ pinned Unipacker 1.0.8 и лимит 65 536 интервалов. Превышение лимита не
меняет прежнее состояние. Общий `merge_write_ranges` остаётся для других вызовов.

`src/unpacker/unpackers/_unipacker_shared.py`: заменена только write-ветка
callback, с сохранением статистики секций, breakpoints, логирования, обработки
ошибок и делегирования чтений. Замена списка внешним вызывающим кодом вызывает
повторную нормализацию. `write_tracking` сохраняет счётчики и лимит в результате
и в ограниченном progress-файле, в том числе перед тайм-аутом.

### Быстрый путь для уже определённой секции загрузчика

`_generic_handoff_eligible` больше не сканирует каждый write interval, когда
секция уже классифицирована как loader. Решение остаётся тем же: текущий адрес
должен пройти текущую raw-границу. Не менялись условия перехода, разрешения,
проверки reconstruction или частичные статусы. Восемь проверок покрывают границу
и оба состояния разрешения импортов; рандомизированная проверка write tracker
сравнивает покрытие с независимым множеством байтов.

### AI получает конкретные ограничения partial

OpenAI CLI по умолчанию выбирает `gpt-6.1-sol`; `--model` переопределяет модель,
`--model-from-env` явно включает прежний env-driven выбор. Общий credential file
не меняется. Эта настройка была применена в предыдущем этапе; сейчас она
сохранена и её шесть тестов добавлены в offline AI job.

Новый allowlist `partial_causes` в `ai/run_contracts.py` различает восемь
категорий: inferred execute permission, omitted noncontiguous allocations,
inferred headers, approximated cache, recovered erased import names, modeled
interactive response, unreconstructed VFS/TLS и `other`. Collector сопоставляет
только точные известные диагностики; произвольные строки превращаются в `other`.
Дубликаты и причины partial при другом outcome отклоняются. Пути, адреса, код,
сырые warnings и имена образцов не экспортируются.

Prompt `run-advisor-2.2` просит объяснять фактически указанную причину. Прохождение
gate не разрешает модели повышать partial до полного восстановления. Advice
по-прежнему не исполняет код/команды, не патчит образец, не меняет UnpackResult
и не запускает retries. Офлайн-проекция всех 54 предыдущих отчётов прошла.

### Гостевая реализация lstrcatA

В `crt_buffers.py`/`winapi_model.py` добавлена ограниченная stdcall-реализация:
чтение NUL-terminated ANSI-байтов, append и NUL в гостевой памяти, возврат
исходного destination. NULL и Unicorn access fault возвращают NULL. Перекрытие
буферов, PE32 overflow и превышение общего byte budget явно останавливаются,
без выдуманного успеха. Произвольные внутренние исключения не маскируются под
обычный API failure. Гостевые пути не открываются на хосте.

12 новых unit-тестов проверяют обычные/пустые/не-ASCII строки, неизменность source,
NULL, ошибки read/write, overlap, aggregate budget и stdcall stack. Контракт
сверен с [Microsoft lstrcatA](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lstrcata).
Это ограниченная эмуляция существующего API, а не рекомендация применять его
в новом host-коде.

## Производительность и честная оценка Molebox

В промежуточном полном прогоне на 390 тестах Molebox вместо timeout дошёл до
явного unsupported `lstrcatA` за 53.93 с. Затем этот API был реализован.
Отдельный новый Molebox-прогон завершился timeout за 60.59 с; последняя запись
прогресса не доказывает, что новый API уже был вызван. Нельзя считать это
подтверждением успешного обхода прежней остановки. Окончательный полный прогон:
Molebox `failed` за 55.54 с.
В нём уже зафиксированы четыре вызова `lstrcatA`, затем trial-диалог Molebox 2.5
«Execute the program?» (`MB_YESNO`) и ответ модели `IDNO` (7). После этого гостевой
`ExitProcess(0)` срабатывает до handoff. Здесь достижение нового API подтверждено,
а дальнейшая остановка связана с выбранной политикой неинтерактивного диалога.
Это не доказательство успешной реконструкции: сохранены три ранее отклонённых
кандидата, включая неготовый IAT и отсутствие реконструированных импортов.

EXpressor в промежуточном полном прогоне занял 33.28 с, при прежнем повторе
48.98 с; в окончательном прогоне — 43.66 с,
`partial`. Это отдельные измерения на общем хосте, без гарантии
ускорения на других машинах/образцах. Причинность и стабильный процент ускорения
не установлены одними wall-time замерами.

Микробенчмарки на сгенерированных данных, три повторения каждого метода:
25 000 покрытых записей, 64 интервала — медианы 0.49245 → 0.01610 с;
25 000 вызовов известного loader, 64 интервала — 0.14170 → 0.01540 с.
Эти результаты относятся к двум узким операциям, не ко всему Unpacker.

## Почему EXpressor по-прежнему partial

Ограниченная трасса VirtualProtect/применения прав на incremental snapshot
зафиксировала handoff в 0x40532c. Заголовок первой секции не содержит execute;
среди явных successful protection transitions есть страницы 0x400000 и
0x406000, но не entry page 0x405000. В момент handoff нет pending transition.
Изначально permissive mapping backend не является доказательством запрошенных
Windows-прав. Поэтому inferred execute permission остаётся явно частичным
восстановлением даже при 7/7 статических критериях.

Первый диагностический запуск прежней версии сам достиг hard timeout 60 с;
его неудача сохранена. Более поздняя incremental-трасса завершилась и сохранена
отдельно. Нельзя выдавать её за trace окончательного snapshot: hashes и область
каждой проверки приведены в сопутствующих JSON.

## Полная матрица окончательного прогона

PE gates: executable bytes, entry RVA, entry mapping, imports, loader-ready IAT,
import descriptors, machine. `—` означает отсутствие этого PE-сравнения.
Для ELF exact match, vendor validation и structural-only смысл различается;
`extracted` — статус инструмента в указанных границах проверки, не доказательство
полной поведенческой эквивалентности, восстановления всех TLS/resources или
VMProtect devirtualization.

| ID | Семейство | Статус | Валидация | PE gates | Секунды |
|---|---|---|---|---|---:|
| case0001 | ASPack | extracted | known_answer_verified | 7/7 | 12.96 |
| case0002 | Alienyze | failed | not_checked | — | 12.79 |
| case0003 | Amber | timeout | not_checked | — | 60.73 |
| case0004 | BeRoEXEPacker | extracted | known_answer_verified | 7/7 | 5.74 |
| case0005 | EXpressor | partial | known_answer_verified | 7/7 | 43.66 |
| case0006 | Enigma Virtual Box | partial | known_answer_verified | 7/7 | 0.99 |
| case0007 | Eronana Packer | partial | known_answer_verified | 7/7 | 7.22 |
| case0008 | Exe32pack | partial | known_answer_verified | 7/7 | 2.97 |
| case0009 | FSG | partial | known_answer_verified | 7/7 | 4.02 |
| case0010 | JDPack | partial | partial | 6/7 | 2.75 |
| case0011 | MEW | extracted | known_answer_verified | 7/7 | 3.85 |
| case0012 | MPRESS | extracted | known_answer_verified | 7/7 | 28.06 |
| case0013 | Molebox | failed | not_checked | — | 55.54 |
| case0014 | NSPack | extracted | known_answer_verified | 7/7 | 31.90 |
| case0015 | Neolite | partial | known_answer_verified | 7/7 | 2.64 |
| case0016 | PECompact | extracted | known_answer_verified | 7/7 | 5.59 |
| case0017 | PEtite | failed | not_checked | — | 2.29 |
| case0018 | Packman | extracted | known_answer_verified | 7/7 | 4.79 |
| case0019 | RLPack | failed | not_checked | — | 6.39 |
| case0020 | TELock | failed | not_checked | — | 1.33 |
| case0021 | Themida | timeout | not_checked | — | 60.82 |
| case0022 | UPX | extracted | known_answer_verified | 7/7 | 1.01 |
| case0023 | WinUpack | unsupported | not_checked | — | 0.68 |
| case0024 | Yoda-Crypter | failed | not_checked | — | 4.24 |
| case0025 | Yoda-Protector | failed | not_checked | — | 0.94 |
| case0026 | ezuri | extracted | known_answer_verified | — | 1.29 |
| case0027 | gzexe | extracted | known_answer_verified | — | 0.89 |
| case0028 | midgetpack | unsupported | not_checked | — | 0.73 |
| case0029 | pakkero | unsupported | not_checked | — | 0.95 |
| case0030 | upx | extracted | known_answer_verified | — | 1.14 |
| case0031 | ward | extracted | known_answer_verified | — | 1.44 |
| case0032 | UPX | extracted | structurally_valid | — | 1.55 |
| case0033 | UPX | extracted | structurally_valid | — | 1.53 |
| case0034 | UPX | extracted | structurally_valid | — | 1.63 |
| case0035 | UPX | extracted | structurally_valid | — | 1.53 |
| case0036 | UPX | extracted | structurally_valid | — | 1.55 |
| case0037 | UPX | extracted | structurally_valid | — | 1.49 |
| case0038 | UPX | extracted | structurally_valid | — | 1.64 |
| case0039 | UPX | extracted | structurally_valid | — | 1.69 |
| case0040 | UPX | extracted_vendor_format | vendor_validated | — | 0.83 |
| case0041 | UPX | extracted_vendor_format | vendor_validated | — | 0.99 |
| case0042 | UPX | extracted | structurally_valid | — | 1.59 |
| case0043 | UPX | extracted | structurally_valid | — | 1.48 |
| case0044 | UPX | extracted | structurally_valid | — | 1.49 |
| case0045 | UPX | extracted | structurally_valid | — | 1.53 |
| case0046 | UPX | extracted_vendor_format | vendor_validated | — | 0.91 |
| case0047 | UPX | extracted | structurally_valid | — | 1.59 |
| case0048 | UPX | extracted | structurally_valid | — | 1.54 |
| case0049 | UPX | extracted | structurally_valid | — | 1.75 |
| case0050 | UPX | extracted | structurally_valid | — | 1.61 |
| case0051 | UPX | extracted | structurally_valid | — | 1.64 |
| case0052 | UPX | extracted | structurally_valid | — | 1.63 |
| case0053 | VMProtect | unsupported | not_checked | — | 1.83 |
| case0054 | YZPack | timeout | not_checked | — | 60.57 |

## Оставшиеся барьеры и следующий инженерный шаг

Ни один провал не объявляется решённым только по signature match или AI-ответу.
Точные сообщения ниже — наблюдения, а не автоматически доказанные первопричины.

| ID | Семейство | Наблюдение |
|---|---|---|
| case0002 | Alienyze | Emulated CPU stopped: UcError: Invalid memory fetch (UC_ERR_FETCH_UNMAPPED) |
| case0003 | Amber | Emulation hard deadline exceeded |
| case0013 | Molebox | Guest ExitProcess(0x00000000) before reconstruction handoff |
| case0017 | PEtite | Emulated CPU stopped: UcError: Write to write-protected memory (UC_ERR_WRITE_PROT) |
| case0019 | RLPack | Emulated CPU stopped: UcError: Unhandled CPU exception (UC_ERR_EXCEPTION) |
| case0020 | TELock | Emulated CPU stopped: UcError: Invalid instruction (UC_ERR_INSN_INVALID) |
| case0021 | Themida | Emulation hard deadline exceeded |
| case0023 | WinUpack | Nonempty input import directory is malformed; custom loader needed |
| case0024 | Yoda-Crypter | Unmapped emulated memory access: {'access': 19, 'address': 8536256, 'size': 1} |
| case0025 | Yoda-Protector | Emulated CPU stopped: UcError: Unhandled CPU exception (UC_ERR_EXCEPTION) |
| case0028 | midgetpack | Unipacker requires a valid PE32 file |
| case0029 | pakkero | Unipacker requires a valid PE32 file |
| case0053 | VMProtect | Emulation callback stopped: UnsupportedAPI: GetDC: API semantics are not implemented |
| case0054 | YZPack | Emulation hard deadline exceeded |

Следующие проверяемые milestones:

1. **Molebox:** явная, журналируемая опция выбора ответа гостевому YES/NO-диалогу
   с сохранением текущего default и отметки modeled interaction. Затем проверить
   IAT/entry на выбранной ветке. Критерий — строгие reconstruction gates в 60 с;
   выбор Yes сам по себе не означает восстановление. Это ещё не реализовано.
2. **Amber/Themida/YZPack:** bounded профиль hot paths и повторяемые benign
   fixtures для декодеров. Критерий — завершение в 60 с и прежние gates,
   с сохранением всех timeout-результатов. Рост deadline не считается исправлением.
3. **PEtite и CPU faults:** изолированная референсная Windows-трасса и независимо
   воспроизводимый вариант пакера. Сейчас эта инфраструктура/трасса отсутствует.
   Нельзя отключать protection или трактовать CPU exception как доказанный
   недостаток конкретной инструкции/SEH без трассы.
4. **WinUpack/ELF:** custom loader для malformed imports и отдельные поддержанные
   ELF-loader backend для midgetpack/pakkero. Это отсутствующие реализации,
   не исправляемые добавлением signature. Qiling rootfs и новые runtime-компоненты
   не устанавливались и не получались в этом этапе.
5. **Partial:** нужны независимые проверки восстановленных allocations, TLS/VFS,
   permissions/cache/interactive assumptions; JDPack также не проходит сравнение
   executable bytes. Прохождение остальных критериев не отменяет эти ограничения.
6. **AI:** оценка диагностики на размеченном наборе неизменяемых исходов после
   разрешения внешней передачи конкретных метаданных. Измерять grounding и
   пригодность следующего диагностического шага, не придумывать recovery rate LLM.

## Внешний AI-запрос: выполнен только preview

В этом этапе живого обращения по реальному отчёту не было. Автоматическая проверка
разрешений отклонила передачу 584-байтного JSON, полученного из частного EXpressor
report, в `https://api.openai.com/v1/chat/completions`, модель `gpt-6.1-sol`:
нет отдельного согласия на этот payload и destination. Команда не была исполнена;
обход и повторная отправка другим способом не проводились. Ключи в этом этапе
не читались и не копировались. Ранее Sol проверялся на синтетических данных;
это не заменяет согласие на приватные данные и не доказывает улучшения recovery.

Точный JSON подготовлен локально: `sol-expressor-payload.json` (585 байт с
завершающим LF; канонический JSON — 584 байта). SHA-256 канонического JSON:
`6cb7a3555e5a50adb2c72eff0e7b9581faeb07283a42c2b938b8fef430d2965d`.
Даже allowlisted метаданные раскрывают сведения о частном анализе. Для отправки
именно этого содержимого в OpenAI требуется явное согласие пользователя.

## Воспроизводимость и доказательства

Окончательный fingerprint 63 Python-файлов:
`765c1f77ca699e44ca24377a9fe964136eee5416023a2fa673cfd94896e04f1b`. Формат: SHA-256 compact sorted JSON mapping
относительных путей на SHA-256 байтов файлов.

Локальный каталог доказательств:
`/private/local-validation-workspace/sol-dev-evidence/`.

* `whole-corpus-402/pass-summary.json`: все 54 строки на окончательном source;
  каждый case также содержит source hashes, invocation, process, report и stdout/stderr.
* `whole-corpus-390/` и `source-390.zip`: полный предшествующий snapshot и его
  результаты до добавления гостевого lstrcatA.
* `candidate-402-tests.xml`, `comparison-402.json`, `frozen-source-402.json`,
  `corpus-integrity.json`: тесты, точные различия, исходный snapshot и хеши корпуса.
* `focused-runtime/`, `molebox-lstrcat-402/`, `expressor-protection-baseline/`,
  `expressor-protection-incremental/`: ограниченные эксперименты, включая неудачи.
* Два `*-microbenchmark.json`, `partial-cause-projection-audit.json`,
  `ai-request-blocked.json`: узкие измерения, offline projection и неисполненный
  внешний запрос.
* `applied-changes.json` и `applied-tests.xml` фиксируют перенос только проверенных
  дельт в рабочий репозиторий. После переноса прошли 402 теста за 9.28 с;
  release gate подтвердил ноль skip/failure/error, `git diff --check` прошёл.
  Все 63 исходных Python-файла совпали с полным прогоном. Прежний собранный wheel
  не представляет этот snapshot; готовность продакшн-релиза здесь не заявляется.

Исторические baseline и этот snapshot сохранены отдельно. Наблюдаемых улучшений
полноты восстановления в этом этапе не приписывается: основной результат —
ускоренные ограниченные операции, более точная диагностика и проверенная модель API.
