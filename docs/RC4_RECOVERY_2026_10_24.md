# Unpacker RC4: возобновление разработки и проверка восстановления

Дата: 2026-10-24T10:56:12.247606+00:00. Это локальный кандидат, не опубликованный релиз.

## Проверенный итог

Завершён один новый последовательный прогон всех 54 файлов на одном установленном wheel RC4.
Результат: **33 принятых, 8 partial, 7 failed,
3 timeout, 3 unsupported**.
Принятые статусы учитываются отдельно: `{'extracted': 30, 'failed': 7, 'timeout': 3, 'partial': 8, 'unsupported': 3, 'extracted_vendor_format': 3}`.
Полное восстановление всех упаковщиков не достигнуто. Приёмка проверяет статические свойства,
а не поведенческую эквивалентность или де-виртуализацию VMProtect/Themida.

Исходный набор: **492 теста** (8,72 с); установленный пакет: **492 теста** и **11 проверок**.
Добавлены 27 тестов Pakkero и 17 тестов идентичности модулей/наблюдений импортов относительно RC2 (448 тестов).
Целевой регрессионный набор последнего исправления: 57 тестов.

- Wheel: `1200km_unpacker-1.2.0rc4-py3-none-any.whl`.
- SHA-256: `803017c9784b71a2f9801d737531b776a7eec4854c8900fa22f6a5154e9c90bb`.
- Runtime: 68 Python-файлов; точные хеши в proof archive.
- Период полного прогона: 2026-10-24T10:49:06.133465+00:00 — 2026-10-24T10:55:45.479723+00:00.
- Длительность: 399.346 с.
- Decode/job: 60/75 с; совокупный выход 32 MiB; внешний watchdog 85 с.
- 52 зависимости из прежнего hash-locked wheelhouse; системные site-packages выключены.
- Runtime и зависимости до/после прогона идентичны. Проверены файлы, установленные из dependency wheels;
  отдельный вспомогательный `readelf.py` и bootstrap pip описаны отдельно в environment record.
- Базовый Git commit: `29dd691bd339ead5e6bd080a976e2ee2f12c3d63`, ветка main, рабочее дерево с локальными изменениями.
  Commit, push, публикация, деплой и изменение host security не выполнялись.

## Что реализовано

### Статическое извлечение Pakkero

Реализован узкий профиль ELF64 little-endian x86_64 с UPX-носителем, Unicode-числовым offset,
SHA512/256-ключом от неизменённого префикса входа и обязательной проверкой AES-GCM tag.
Декодер проверяет PackHeader, ограничивает размеры и число кандидатов, восстанавливает изменённую
сигнатуру только во временной копии, вызывает установленный UPX для декомпрессии и проверяет результат.
Launcher и извлечённая программа не исполняются. Процесс UPX остаётся в группе ограниченного worker;
временные файлы очищаются; распаковка zlib/base64 ограничена; выход имеет режим 0600.

Реальный case0029 аутентифицируется, но payload **равен собственному префиксу входного файла**:
offset и длина 752299 байт, SHA-256 `c372a0b29f7eaeffb490cb35d1b56e00a57616b1ba1802608bf4d627b0b901b8`.
Это не восстановленный парный ls размером 142144 байта. Статус остаётся partial, success=False.
Предположение об ошибке упаковки in-place согласуется с исходниками/рецептом, но без исходного
журнала генерации не является доказанной причиной происхождения данного образца.

Отдельный безопасный сквозной опыт получил точное совпадение с минимальным известным ELF.
Это синтетический совместимый контейнер с метаданными, скомпилированными GCC и сжатыми UPX внутри
sandbox; upstream Pakkero при его создании не запускался. Pipeline сохранил
`extracted_with_residual_evidence`, хотя known-answer проверка байтов успешна.
Этот опыт не добавлен к 54 реальным fixtures и не выдаётся за отдельную версию upstream packer.

Код: `src/unpacker/pakkero_format.py:16`, `:33`, `:54`, `:89`;
`src/unpacker/unpackers/pakkero.py:18`; тесты `tests/test_pakkero.py`.

### Molebox: исправлена идентичность HMODULE

Доказанный прежний сбой: backend возвращал для именованного GetModuleHandleA непрозрачный
идентификатор, который сначала совпадал с базой EXE. Molebox трактовал DOS-заголовок EXE как
таблицу экспорта kernel32 и обращался по адресу 0x2b31839c из инструкции 0x41f5a9.

Новый GuestModules берёт идентичность из заранее проверенных отображённых образов loader list.
Для kernel32 возвращается 0x755d0000; учитываются регистр, отсутствие расширения, Windows-путь,
NULL/основной EXE, границы отображения и коллизии. Повреждение заголовка гостем не меняет уже
установленную идентичность загруженного модуля. Windows reference count не увеличивается.
Модель не загружает host DLL. Неизвестные модули остаются на явно обозначенном legacy-пути;
полный LoadLibrary/unload и произвольные DLL не реализованы.

Первый RC4 обнаружил реальную регрессию ASPack: объединение наблюдений двух последовательностей
lookup исключало 32 импорта kernel32 (53 вместо 85). Общий прогон был остановлен после
обнаружения регрессии, его доказательства и исходники сохранены. Вариант v2 разделяет
последовательности наблюдений при стабильном HMODULE. Backend counter здесь выбирает группу
наблюдений, а не моделирует OS reference count. Повторный ASPack прошёл все 7 ворот и 85 импортов.

Molebox прошёл прежнюю точку сбоя. Полное восстановление пока не достигнуто: candidate IAT
проваливает строгую проверку терминатора; после 64 отклонённых кандидатов срабатывает существующий
лимит. В диагностике видны kernel32/user32/gdi32-таблицы, повторные lookup и ненулевое продолжение
выбранного IAT. Нельзя обнулять соседний указатель или принимать ранний loader dump без доказательств.
Ограничение относится к stage-aware handoff и реконструкции IAT, а не к отсутствующему API-ключу.

Код: `src/unpacker/guest_modules.py:9`, `src/unpacker/loader_lists.py:31`,
`src/unpacker/winapi_model.py:138`, `src/unpacker/unpackers/_unipacker_shared.py:405`;
тесты `tests/test_guest_modules.py`.
Microsoft определяет HMODULE как адрес загрузки и описывает GetModuleHandle без увеличения счётчика:
[MODULEINFO](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-moduleinfo),
[GetModuleHandleA](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea).

## Сравнение с RC2 и правила приёмки

Исходные 54 файла не означают 54 независимые программы. Есть 32 нормализованных source-family
label, включая 23 UPX-варианта. У 31 файла есть парный оригинал, представляющий 12 уникальных
хешей программ. Версии, архитектуры и поведение представлены ограниченно. Знаменатель сохранён.

Для PE32 с оригиналом проверяются: байты исполняемых секций по RVA, исходный entry RVA,
file-backed executable mapping точки входа, набор импортов, loader-ready IAT,
строгая таблица дескрипторов и machine. Расхождение любого ворота исключает known-answer приёмку.
Для статических ELF/wrapper fixtures проверяется точное совпадение с оригиналом, когда он есть.
Vendor-format приёмка для DOS/COFF/TOS опирается на vendor decoder и отмечена отдельно.
Предупреждения об inferred execute permission, noncontiguous allocations, отсутствующих VFS/TLS
и других приближениях сохраняют partial даже при успешном наборе отдельных статических проверок.

Нет нативного запуска specimens, обращения к реальному GUI гостя или изменения изоляции.
Частичные результаты, таймауты и failed не считаются успехом. Новые private LLM-запросы не отправлялись;
проверка AI в этой серии — offline preview. Совет модели не заменяет evidence gates.

Сохранены принятые RC2: 33/33. Новые принятые: []; потери: [].

Все различия status/validation/gates/error с RC2 перечислены ниже; различия сообщений не равны улучшению восстановления.

- **case0013 Molebox**: {"error": {"before": "Unmapped emulated memory access: {'access': 19, 'address': 724665244, 'size': 1}", "after": "Emulation callback stopped: ValueError: Generic handoff candidate budget exceeded"}}
- **case0029 pakkero**: {"status": {"before": "unsupported", "after": "partial"}, "validation": {"before": "not_checked", "after": "partial"}, "error": {"before": "Unipacker requires a valid PE32 file", "after": "Authenticated payload equals its own carrier prefix; original application recovery is not established"}}

## Полная матрица 54 файлов

Точные хеши входов/оригиналов, reports и времена находятся в `corpus-manifest.json` и `evidence/rc4/unified-rc4-v2-wheel-54/`.

| ID | Source-family | Результат | Validation | PE-ворота | Время, с | Причина / ограничение |
|---|---|---|---|---|---:|---|
| case0001 | ASPack | extracted | known_answer_verified | 7/7 | 7.739 | Принят в указанном scope |
| case0002 | Alienyze | failed | not_checked | — | 7.537 | Emulated CPU stopped: UcError: Invalid memory fetch (UC_ERR_FETCH_UNMAPPED) |
| case0003 | Amber | timeout | not_checked | — | 60.341 | Emulation hard deadline exceeded |
| case0004 | BeRoEXEPacker | extracted | known_answer_verified | 7/7 | 3.579 | Принят в указанном scope |
| case0005 | EXpressor | partial | known_answer_verified | 7/7 | 28.582 | Degraded emulation dump |
| case0006 | Enigma Virtual Box | partial | known_answer_verified | 7/7 | 0.673 | Embedded virtual filesystem and wrapper TLS behavior are not reconstructed |
| case0007 | Eronana Packer | partial | known_answer_verified | 7/7 | 4.481 | Degraded emulation dump |
| case0008 | Exe32pack | partial | known_answer_verified | 7/7 | 1.324 | Degraded emulation dump |
| case0009 | FSG | partial | known_answer_verified | 7/7 | 2.276 | Degraded emulation dump |
| case0010 | JDPack | partial | partial | executable_bytes | 1.876 | Degraded emulation dump |
| case0011 | MEW | extracted | known_answer_verified | 7/7 | 2.477 | Принят в указанном scope |
| case0012 | MPRESS | extracted | known_answer_verified | 7/7 | 17.962 | Принят в указанном scope |
| case0013 | Molebox | failed | not_checked | — | 53.980 | Emulation callback stopped: ValueError: Generic handoff candidate budget exceeded |
| case0014 | NSPack | extracted | known_answer_verified | 7/7 | 27.383 | Принят в указанном scope |
| case0015 | Neolite | partial | known_answer_verified | 7/7 | 1.976 | Degraded emulation dump |
| case0016 | PECompact | extracted | known_answer_verified | 7/7 | 5.085 | Принят в указанном scope |
| case0017 | PEtite | failed | not_checked | — | 1.874 | Emulated CPU stopped: UcError: Write to write-protected memory (UC_ERR_WRITE_PROT) |
| case0018 | Packman | extracted | known_answer_verified | 7/7 | 3.979 | Принят в указанном scope |
| case0019 | RLPack | failed | not_checked | — | 5.483 | Emulated CPU stopped: UcError: Unhandled CPU exception (UC_ERR_EXCEPTION) |
| case0020 | TELock | failed | not_checked | — | 0.924 | Emulated CPU stopped: UcError: Invalid instruction (UC_ERR_INSN_INVALID) |
| case0021 | Themida | timeout | not_checked | — | 60.553 | Emulation hard deadline exceeded |
| case0022 | UPX | extracted | known_answer_verified | 7/7 | 0.673 | Принят в указанном scope |
| case0023 | WinUpack | unsupported | not_checked | — | 0.421 | Nonempty input import directory is malformed; custom loader needed |
| case0024 | Yoda-Crypter | failed | not_checked | — | 3.278 | Unmapped emulated memory access: {'access': 19, 'address': 8536256, 'size': 1} |
| case0025 | Yoda-Protector | failed | not_checked | — | 0.672 | Emulated CPU stopped: UcError: Unhandled CPU exception (UC_ERR_EXCEPTION) |
| case0026 | ezuri | extracted | known_answer_verified | — | 0.980 | Принят в указанном scope |
| case0027 | gzexe | extracted | known_answer_verified | — | 0.625 | Принят в указанном scope |
| case0028 | midgetpack | unsupported | not_checked | — | 0.471 | Unipacker requires a valid PE32 file |
| case0029 | pakkero | partial | partial | — | 0.825 | Authenticated payload equals its own carrier prefix; original application recovery is not established |
| case0030 | upx | extracted | known_answer_verified | — | 0.823 | Принят в указанном scope |
| case0031 | ward | extracted | known_answer_verified | — | 0.874 | Принят в указанном scope |
| case0032 | UPX | extracted | structurally_valid | — | 1.026 | Принят в указанном scope |
| case0033 | UPX | extracted | structurally_valid | — | 1.028 | Принят в указанном scope |
| case0034 | UPX | extracted | structurally_valid | — | 1.076 | Принят в указанном scope |
| case0035 | UPX | extracted | structurally_valid | — | 1.026 | Принят в указанном scope |
| case0036 | UPX | extracted | structurally_valid | — | 0.925 | Принят в указанном scope |
| case0037 | UPX | extracted | structurally_valid | — | 1.076 | Принят в указанном scope |
| case0038 | UPX | extracted | structurally_valid | — | 0.977 | Принят в указанном scope |
| case0039 | UPX | extracted | structurally_valid | — | 1.075 | Принят в указанном scope |
| case0040 | UPX | extracted_vendor_format | vendor_validated | — | 0.624 | Принят в указанном scope |
| case0041 | UPX | extracted_vendor_format | vendor_validated | — | 0.625 | Принят в указанном scope |
| case0042 | UPX | extracted | structurally_valid | — | 1.024 | Принят в указанном scope |
| case0043 | UPX | extracted | structurally_valid | — | 1.177 | Принят в указанном scope |
| case0044 | UPX | extracted | structurally_valid | — | 0.875 | Принят в указанном scope |
| case0045 | UPX | extracted | structurally_valid | — | 1.025 | Принят в указанном scope |
| case0046 | UPX | extracted_vendor_format | vendor_validated | — | 0.525 | Принят в указанном scope |
| case0047 | UPX | extracted | structurally_valid | — | 1.129 | Принят в указанном scope |
| case0048 | UPX | extracted | structurally_valid | — | 1.128 | Принят в указанном scope |
| case0049 | UPX | extracted | structurally_valid | — | 1.127 | Принят в указанном scope |
| case0050 | UPX | extracted | structurally_valid | — | 1.127 | Принят в указанном scope |
| case0051 | UPX | extracted | structurally_valid | — | 1.176 | Принят в указанном scope |
| case0052 | UPX | extracted | structurally_valid | — | 1.128 | Принят в указанном scope |
| case0053 | VMProtect | unsupported | not_checked | — | 1.275 | Emulation callback stopped: UnsupportedAPI: GetSysColorBrush: API semantics are not implemented |
| case0054 | YZPack | timeout | not_checked | — | 60.354 | Emulation hard deadline exceeded |

## Что остаётся и что необходимо дальше

| Приоритет | Работа | Недостающая возможность / вход | Критерий приёмки |
|---|---|---|---|
| P0 | Molebox: stage-aware handoff и import provenance | Реконструктор должен отличать loader helpers от OEP, связывать конкретные IAT slots с наблюдёнными module/symbol и сохранять соседние данные. Текущий first-match backend этого не обеспечивает. Это инженерная задача, не permission blocker. | Синтетические duplicate/nonterminated/multi-sequence tables; ноль изменений живой памяти; реальный case0013 проходит исходные 7 ворот; прежние 33 accepted сохранены. |
| P0 | Допуск Linux CLI к выпуску | Открытая проверка advisories/applicability, legacy emulator dependency chain, удалённый target CI и dedicated disposable worker/cgroup acceptance не закрыты. | Проверенный dependency disposition, CI по точному SHA, проверка квот/очистки на целевом worker; отдельное разрешение на публикацию. |
| P1 | Исключения CPU/SEH: PEtite, RLPack, TELock, Yoda | Поддержан только узкий AV/ContinueExecution профиль; полноценные INT3/ICEBP, search/unwind/vectored/top-level dispatch отсутствуют. Для подтверждения fidelity нужны эталонные Windows traces/синтетические state vectors. | Точное восстановление CPU/stack/protection transitions, без NOP/фиктивного success; исходные gates каждого fixture. |
| P1 | Изоляция стадий и deadline cases: Amber, Themida, YZPack | Требуется отдельный bounded профиль горячих циклов и handoff, а не увеличение лимита. Де-виртуализация не реализована. | Новый результат под теми же 60/75 с; воспроизводимый профиль и unchanged accepted regressions. |
| P1 | VMProtect: GUI/GDI объекты и callback lifecycle | Сейчас моделируются DC capabilities/цвета, но не полный GetSysColorBrush, ownership/select/delete объектов, окна и drawing. Нужен связный guest object model и эталонные состояния. | Stateful benign tests и исходные PE gates; поддержка отдельных GUI API не объявляется devirtualization. |
| P1 | WinUpack / Alienyze / Yoda-Crypter | Custom loader для malformed imports, доказанный layout/entry mapping, fault provenance. Текущие ошибки не доказывают отсутствие payload. | Reference-free reconstruction плюс paired original checks; нет подстановки оригинала в выход. |
| P1 | Partial Enigma/Eronana/Exe32pack/Neolite | Embedded VFS/TLS, раздельные allocations, erased headers и incomplete process ABI. | Сохранение всех требуемых ресурсов/allocations и явная проверка семантики; не только core PE. |
| P1 | JDPack / EXpressor / FSG | JDPack: ранее 366 различий в import data, но строгий byte gate не пройден. EXpressor/FSG: execute permission выведено из handoff. | Доказанная реконструкция без предположений; исходные gates, предупреждения не подавляются. |
| P2 | Pakkero: больше подлинных fixtures | Нужны корректно сгенерированные upstream fixtures с раздельными input/output и известными оригиналами. Текущий реальный файл self-embeds; synthetic fixture не заменяет его. | Несколько подлинных известных оригиналов/версий; tag failure и self-prefix остаются отвергнуты. |
| Вход блокирует | midgetpack | Пароль отсутствует. Зашифровано 10112 байт; проверка показывает 20000 KDF iterations. Пароль нельзя заменить модельным предположением или dummy decryption. | Правильный предоставленный пароль и точное сравнение с оригиналом. |

Следующий ограниченный milestone: Molebox import-provenance rebuilder с benign fixtures и реальным
paired acceptance. Сначала следует сохранить slot provenance при разрешении API, затем строить
новую lookup/descriptor область только в доказанном свободном workspace. Если IAT не имеет
безопасного нулевого терминатора, нельзя затирать следующий указатель. Перенос потребует доказанных
ссылок кода/данных или сохранения partial. Эталонный оригинал используется только для проверки.

## Релиз, воспроизводимость и ограничения

Решение: **NO-GO для production/public release**. Локальный analyst candidate подготовлен и проверен
в указанном окружении; универсальная эффективность не заявляется. Resource supervisor и namespace
sandbox сохраняют прежние ограничения, однако это не заменяет отдельный disposable-worker security
acceptance и cgroup enforcement. Предложенные worker profiles на host не применялись.

RC2/RC3, неудачные опыты и первый RC4 wheel сохранены. Первый общий RC4 run прерван намеренно после
регрессии ASPack; он не является полным прогоном. Итоговая матрица выше использует только v2 wheel,
без смешения source/dependency snapshots и без повторного использования прежних строк.
Далее нужен review точного локального diff; автоматическая публикация не выполнялась.

В архиве доказательств находятся JSON reports, XML/test logs, identity records, исходники безопасных
проверочных harnesses и изменённых модулей, diff и ledger. Исполняемые specimens, дампы payload,
оригинальные программы, .env и API-ключи исключены. Wheel содержит инструмент, а не corpus specimens.

## Публичные первичные источники форматов

- [Pakkero 0.6.0](https://github.com/89luca89/pakkero/tree/0.6.0): main.go, internal/pakkero/pakkero.go,
  encryption.go, obfuscation.go и data/launcher.go. Формат выведен из исходников; совместимость иных профилей не доказана.
- [UPX PackHeader](https://github.com/upx/upx/blob/v4.2.2/src/packhead.cpp) и
  [Unix packer implementation](https://github.com/upx/upx/blob/v4.2.2/src/p_unix.cpp).

Полные исторические архитектурные/AI/containment результаты находятся в ранее доставленном
`Unpacker-21-case-Investigation-RU-2026-10-24.md` и его RC2 proof archive. Этот отчёт добавляет
новые RC3/RC4 изменения и самостоятельную свежую матрицу, не переписывая исторические измерения.
