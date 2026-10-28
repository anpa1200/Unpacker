# AI-диагностика и защита гостевых страниц — 22 октября 2026

Локальный этап разработки Unpacker, без коммитов, публикации и нативного запуска
образцов. Исходная база: `main`, HEAD
`29dd691bd339ead5e6bd080a976e2ee2f12c3d63`, с сохранёнными ранее незакоммиченными
изменениями. Этот документ дополняет исторические отчёты, а не заменяет их.

## Измеренный результат

* 361 автоматический тест прошёл, без пропусков. Финальный запуск из рабочего
  репозитория дополнительно записывается в `applied-tests.xml` в архиве доказательств.
* Полный последовательный прогон 54 существующих файлов: 30 `extracted`,
  3 `extracted_vendor_format`, 7 `partial`, 6 `failed`, 4 `timeout`, 4 `unsupported`.
  Итого 33 принятых результата, 7 частичных и 14 нераспакованных.
* По сравнению с полной базой 288 тестов изменился один результат: EXpressor,
  `timeout` → `partial`, с прохождением всех семи сравнений с оригиналом.
  Наблюдаемых регрессий в статусах принятых результатов и ранее пройденных
  критериях не обнаружено. Это не доказывает отсутствие всех регрессий.
* EXpressor повторно получил `partial` и 7/7 за 48.98 с, после 49.82 с в полном
  прогоне. Стабильность на других машинах и вариантах пакера не установлена.
* Сохранён предел декодирования 60 с, общий предел задания 75 с и sandbox output
  quota 32 MiB. Полный прогон занял 465.51 с. Выполнены 85 проверок хешей входных
  файлов/оригиналов после прогона; соответствие манифесту сохранено.

54 файла не являются 54 независимыми программами: имеется 31 пара с оригиналом,
12 различных хешей оригиналов, повторяющиеся UPX-варианты и 32 нормализованных
названия семейства. Названия использовались как явный выбор backend. Этот прогон
не измеряет полноту детектора, эффективность на всех версиях пакеров или
поведенческую эквивалентность восстановленной программы.

## Что изменено

### AI получает факты реального запуска

`unpacker-ai report.json --from-report --preview` строит точный исходящий JSON
без загрузки ключей и обращения к сети. Обычный вызов с выбранным provider
отправляет только этот разрешённый набор метаданных. Например:

```bash
unpacker-ai /path/to/run/report.json --from-report --preview
unpacker-ai /path/to/run/report.json --from-report --provider openai \
  --env-file /path/to/authorized.env
```

Добавлены `ai/collector.py`, `ai/run_contracts.py`, `ai/policy.py` и версия
`run-advisor-2.1`. Старый evidence/advice-контракт версии 1 сохранён.
Collector читает один явно указанный обычный файл размером до 2 MiB, отклоняет
symlink-файл, дубли ключей и нечисловые/бесконечные JSON-значения. Не более
32 слоёв; канонический экспорт — до 32 KiB. Данные из включённых в отчёт путей
не открываются, исходный образец не читается и не исполняется.

Внешняя модель видит только формат/архитектуру, типизированные признаки, backend,
заявленный результат и валидацию, независимые критерии реконструкции, наличие
сравнения с оригиналом, число отклонённых переходов, ограниченные категории
недостающих API и ошибок гостевого runtime. Адреса, пути, хеши образцов, сырые
логи, строки, код и произвольные названия API исключены. ID генерируются заново.
Архитектура новых отчётов получается из согласованных полей PE/ELF внутри
существующего static worker; в старом отчёте без поля остаётся `unknown`.
`native_integrity` не превращается в ложный признак UPX section names, а confidence
детектора не выдаётся за entropy. Проверки ELF exact-match и vendor validation
сохраняются отдельно от семи PE-критериев.

AI может предложить исследование импортов, перехода в восстановленный код,
входного потока декодера, отсутствующего гостевого API, таймаута, границ частичного
восстановления, расхождений кода или CPU/memory fault. Для категории и действия
требуются подходящие факты именно в указанных ссылках на запуск. Неизвестные ID,
неподдержанное действие и ссылка на другой, неподходящий слой отклоняются.
Provider schema дополнительно ограничивается доступными action/category enum и
существующими ID; route table включается в системный prompt. Локальная проверка
остаётся обязательной даже при таком ограничении генерации.

AI не запускает команды/backend, не изменяет байты, не назначает успех и не
отменяет критерии проверки. Сообщение гостя `Corrupt Data!` не признаётся
доказательством порчи файла, CPU exception — доказанным отсутствием конкретной
инструкции, а все пройденные PE-критерии не повышают `partial` автоматически.
Текст объяснения модели остаётся гипотезой. Сам входной report — недоверенное
утверждение; его SHA-256 обеспечивает связь с локальным файлом, а не подлинность.
Provenance файла, digest экспортированных данных, schema и system prompt сохраняются
локально в результате. Хеш исходного отчёта не отправляется модели.

Выполнена офлайн-проекция всех 54 новых отчётов; наибольший payload — 711 байт.
Это проверка collector/policy, не оценка точности LLM. Четыре живых обращения
к OpenAI GPT-4.1 использовали только синтетические enum-метаданные:
первые два ответа отклонены grounding-проверкой, третий принят после уточнения
prompt, финальный контекстно ограниченный schema/prompt также принят.
Итог не является метрикой 50% или 100% точности: выборка мала, prompt менялся,
нет независимого набора и результата распаковки от модели. Для Claude/Gemini
сохранены офлайн adapter-тесты; живое подключение в этом этапе не проверялось.
Ключи не копировались в проект, артефакты или логи.

### Исправлен VirtualProtect и возврат из callback

Прежняя реализация Unipacker возвращала запрошенный protection value и не
записывала прежние права через `lpflOldProtect`. Добавлен отдельный guest-only
модуль `guest_protection.py`: BOOL-результат, запись предыдущей защиты первой
страницы, округление диапазона по страницам, проверка отображённых страниц и
выходного указателя, смена прав средствами Unicorn и ограниченный учёт переходов.
Неподдержанные guard/COW/modifier-семантики останавливают попытку явно.
Неверные диапазоны и указатели не сообщают ложный успех.

Первая кандидатная версия меняла права непосредственно в API callback, что
привело к повторной обработке API-блока с уже очищенным stdcall-стеком. Эти
неудачные прогоны NSPack/PECompact/PEtite сохранены. В окончательной версии
переход прав выполняется после выхода из `emu_start`; затем восстанавливаются
результат и стек и выполнение продолжается у вызывающего кода. Добавлен
синтетический тест единственного вызова и корректного возврата, а также тесты
реального запрета гостевой записи, границ страниц и отсутствия частичного успеха.
NSPack и PECompact снова проходят 7/7.

Модель имеет явные ограничения: исходные права — существующие mappings backend,
отдельные Windows reserve/commit и shared copy-on-write не реализованы. Это не
полная реализация Windows memory manager. Механизм не делает host API-вызовов.
Требуемая Win32-семантика сверена с
[Microsoft VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect).

### PEtite: подтверждённое наблюдение и оставшаяся неопределённость

Сохранённая трасса и отдельная статическая проверка внутри sandbox показали,
что дескриптор с источником RVA 0, размером `0x896` и назначением RVA 0 уже
находится в исходном файле. Это не артефакт AI и не поздняя правка таблицы нашим
декодером. Ранее при permissive mapping декодер затирал первый байт DOS-заголовка,
читал его как вход сжатого блока и доходил до проверки длины/`Corrupt Data!`.
Теперь после двух корректно учтённых VirtualProtect-переходов запись
`mov [edi],al` в header page с read-only правами приводит к `UC_ERR_WRITE_PROT`.
Это всё ещё не доказывает порчу исходного packed-файла или конкретную недостающую
семантику Windows: нужен независимо воспроизведённый вариант и референсная
изолированная Windows-трасса. Обход проверки, изменение sample и ложный успех
не применялись. Результат остаётся `failed`.

### Release gate и упаковка

Release CI теперь устанавливает уже объявленные optional extras AI SDK,
Unipacker/Unicorn, YAML и cryptography, сохраняет JUnit и отклоняет пустой прогон,
skip, failure и error. Это устраняет путь, при котором release checks могли
незаметно пропустить требуемые тесты из-за отсутствующих зависимостей. Отдельный
AI job включает новые contract/policy tests. Добавлен smoke entrypoint
`unpacker-ai --help`; `MANIFEST.in` включает release-check script и документацию.
Удалённого GitHub Actions run и публикации в этом этапе нет. Успех локальных
проверок не выдаётся за подтверждение CI на всех версиях Python.

## Точная область проверенного исходного кода

Полный 54-файловый прогон выполнен после 354 тестов. После него менялись только
четыре файла в `src/unpacker/ai/` (включая добавление policy): уточнены контекстный
schema и проекция отчётов. Финальная версия прошла 361 тест. Все 54 Python-файла
runtime/детектора/извлечения вне `ai/` побайтно совпадают с полным прогоном.
Это не повторный полный прогон 54 файлов на всех финальных AI-файлах. EXpressor
повторён уже на финальном исходном дереве. Извлечение не импортирует AI-модули;
новая AI-диагностика запускается отдельным явным entrypoint.

Финальный fingerprint 63 Python-файлов:
`f0c5826e7513042ed6c4a17f5e41c3fb7679a3d2666b53edf22126356a668c4d`.
Fingerprint 54 файлов вне AI, совпадающих с полным прогоном:
`75cbddddd0e0ff8fbb8c62aa54cab03b39b49506d64ace6bc96244652c164a84`.
Полные пофайловые SHA-256, версии зависимостей и различия snapshot включены в
`final-verification.json`. Fingerprint — SHA-256 compact sorted JSON mapping
относительных путей на SHA-256 содержимого.

## Матрица полного прогона

«7/7» проверяет executable bytes, entry RVA, entry mapping, imports,
loader-ready IAT, import descriptors и machine. «—» означает отсутствие этого
PE-сравнения, а не ошибку или успех. Для ELF отдельно учитывается точное сравнение
с оригиналом; vendor/native и structural-only статусы имеют более узкий смысл.
Прохождение критериев не доказывает универсальную поведенческую эквивалентность,
восстановление всех ресурсов/TLS или VMProtect devirtualization.

| Файл | Семейство | Было | Сейчас | PE gates | Валидация | Секунды |
|---|---|---|---|---|---|---:|
| case0001 | ASPack | extracted | extracted | 7/7 | known_answer_verified | 10.80 |
| case0002 | Alienyze | failed | failed | — | not_checked | 11.76 |
| case0003 | Amber | timeout | timeout | — | not_checked | 60.33 |
| case0004 | BeRoEXEPacker | extracted | extracted | 7/7 | known_answer_verified | 4.34 |
| case0005 | EXpressor | timeout | partial | 7/7 | known_answer_verified | 49.82 |
| case0006 | Enigma Virtual Box | partial | partial | 7/7 | known_answer_verified | 0.77 |
| case0007 | Eronana Packer | partial | partial | 7/7 | known_answer_verified | 7.22 |
| case0008 | Exe32pack | partial | partial | 7/7 | known_answer_verified | 2.03 |
| case0009 | FSG | partial | partial | 7/7 | known_answer_verified | 2.98 |
| case0010 | JDPack | partial | partial | 6/7 | partial | 2.28 |
| case0011 | MEW | extracted | extracted | 7/7 | known_answer_verified | 2.83 |
| case0012 | MPRESS | extracted | extracted | 7/7 | known_answer_verified | 22.79 |
| case0013 | Molebox | timeout | timeout | — | not_checked | 60.49 |
| case0014 | NSPack | extracted | extracted | 7/7 | known_answer_verified | 36.00 |
| case0015 | Neolite | partial | partial | 7/7 | known_answer_verified | 3.08 |
| case0016 | PECompact | extracted | extracted | 7/7 | known_answer_verified | 5.83 |
| case0017 | PEtite | failed | failed | — | not_checked | 3.08 |
| case0018 | Packman | extracted | extracted | 7/7 | known_answer_verified | 5.19 |
| case0019 | RLPack | failed | failed | — | not_checked | 7.46 |
| case0020 | TELock | failed | failed | — | not_checked | 1.28 |
| case0021 | Themida | timeout | timeout | — | not_checked | 60.66 |
| case0022 | UPX | extracted | extracted | 7/7 | known_answer_verified | 0.93 |
| case0023 | WinUpack | unsupported | unsupported | — | not_checked | 0.62 |
| case0024 | Yoda-Crypter | failed | failed | — | not_checked | 4.48 |
| case0025 | Yoda-Protector | failed | failed | — | not_checked | 0.72 |
| case0026 | ezuri | extracted | extracted | — | known_answer_verified | 1.03 |
| case0027 | gzexe | extracted | extracted | — | known_answer_verified | 0.67 |
| case0028 | midgetpack | unsupported | unsupported | — | not_checked | 0.57 |
| case0029 | pakkero | unsupported | unsupported | — | not_checked | 0.63 |
| case0030 | upx | extracted | extracted | — | known_answer_verified | 0.87 |
| case0031 | ward | extracted | extracted | — | known_answer_verified | 1.02 |
| case0032 | UPX | extracted | extracted | — | structurally_valid | 1.12 |
| case0033 | UPX | extracted | extracted | — | structurally_valid | 1.28 |
| case0034 | UPX | extracted | extracted | — | structurally_valid | 1.48 |
| case0035 | UPX | extracted | extracted | — | structurally_valid | 1.18 |
| case0036 | UPX | extracted | extracted | — | structurally_valid | 1.18 |
| case0037 | UPX | extracted | extracted | — | structurally_valid | 1.38 |
| case0038 | UPX | extracted | extracted | — | structurally_valid | 1.24 |
| case0039 | UPX | extracted | extracted | — | structurally_valid | 1.12 |
| case0040 | UPX | extracted_vendor_format | extracted_vendor_format | — | vendor_validated | 0.67 |
| case0041 | UPX | extracted_vendor_format | extracted_vendor_format | — | vendor_validated | 0.78 |
| case0042 | UPX | extracted | extracted | — | structurally_valid | 1.13 |
| case0043 | UPX | extracted | extracted | — | structurally_valid | 1.13 |
| case0044 | UPX | extracted | extracted | — | structurally_valid | 1.28 |
| case0045 | UPX | extracted | extracted | — | structurally_valid | 1.19 |
| case0046 | UPX | extracted_vendor_format | extracted_vendor_format | — | vendor_validated | 0.63 |
| case0047 | UPX | extracted | extracted | — | structurally_valid | 1.53 |
| case0048 | UPX | extracted | extracted | — | structurally_valid | 1.43 |
| case0049 | UPX | extracted | extracted | — | structurally_valid | 1.38 |
| case0050 | UPX | extracted | extracted | — | structurally_valid | 1.23 |
| case0051 | UPX | extracted | extracted | — | structurally_valid | 1.18 |
| case0052 | UPX | extracted | extracted | — | structurally_valid | 1.23 |
| case0053 | VMProtect | unsupported | unsupported | — | not_checked | 1.73 |
| case0054 | YZPack | timeout | timeout | — | not_checked | 60.40 |

## Следующие инженерные задачи и конкретные ограничения

1. **EXpressor и другие partial.** Для EXpressor нужны доказательства восстановления
   исходных/запрошенных executable permissions, а не повышение статуса по наличию
   7/7. Enigma требует VFS/TLS, Eronana — охвата отдельных live allocations,
   Exe32pack — доказуемого восстановления стёртых headers, FSG — прав исполнения,
   Neolite — cache semantics. У JDPack сохраняется несоответствие executable bytes;
   критерий не ослаблялся. Приёмка: воспроизводимые benign fixtures, независимые
   сравнения и устранение конкретной причины `partial` без копирования оригинала
   в результат.
2. **WinUpack.** Требуется отдельный ограниченный PE loader для наблюдаемой malformed
   import directory; стандартный loader отказывается корректно. Это новый backend
   capability, а не неизвестная зависимость, которую нужно молча установить.
   Приёмка: валидная загрузка без доверия import directory и все семь строгих gates.
3. **PEtite.** Нужны проверенный воспроизводимый packed-файл и референсная трасса
   для дескриптора RVA 0. Без них предполагаемое исправление могло бы скрыть ошибку
   модели или исходного файла. Нативное выполнение образца в этой работе запрещено.
4. **Alienyze, RLPack, TELock, Yoda.** Есть воспроизведённые unmapped fetch/read,
   invalid instruction и CPU exceptions. Их первопричины не установлены. Следующий
   шаг — ограниченные трассы register/operand/exception state и малые benign
   воспроизводители; названия ошибок не объявляются готовым диагнозом CPU/SEH.
5. **Amber, Molebox, Themida, YZPack.** Сохранились таймауты при 60 с. Требуется
   профиль hotspot/повторяющихся переходов и доказанное улучшение без скрытия
   failure или произвольного повышения лимита. Модель советует profile, не меняет
   лимит самостоятельно.
6. **midgetpack/pakkero, PE32+.** Нужны ELF loader/syscall/runtime capability и
   отдельная архитектурная проверка. Qiling rootfs в доступной конфигурации
   отсутствует; новые rootfs, credentials или установки не выполнялись.
7. **VMProtect.** Наблюдаемый blocker — GetDC(NULL); полноценной модели window/DC
   objects нет. Dummy handle не является решением. Обработка этого API также не
   означает devirtualization. Последняя — самостоятельная исследовательская задача.
8. **AI.** Нужен held-out набор независимо воспроизведённых benign программ и
   сравнение с deterministic triage: полезность диагноза, неверные утверждения,
   abstention, время/usage и реальное приращение принятой реконструкции. Следующий
   разумный milestone — ограниченные trace requests через policy/controller с
   отдельным budget и проверкой результата, без исполнения generated code.

Не все проблемы устранены. Текущий результат подходит для дальнейшей проверяемой
разработки и ограниченного аналитического применения; универсальная production
готовность для всех пакеров и близкая к 100% точность не установлены.
