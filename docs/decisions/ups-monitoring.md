# План UPS Monitoring

Статус: утверждённый план, **не реализован**. Следующая работа по этой функции
начинается только отдельной командой пользователя. Версия приложения при реализации
первого этапа не меняется, релиз без отдельной команды не собирается.

## Цель и границы

UPS Monitoring — опциональная специализированная SNMP-подсистема для объектов,
использующая UPS-MIB RFC 1628 (`1.3.6.1.2.1.33`) и, для совместимых APC,
PowerNet MIB (`1.3.6.1.4.1.318.1.1.1`). Это read-only monitoring:
никаких SNMP SET, выключения ИБП, outlet-control, shutdown инфраструктуры, vendor
profiles, SNMP v3, traps, отдельных порогов или отдельного scheduler.

Модуль не создаёт новый SNMP-движок, generic time-series storage или независимый
incident flow. Перед реализацией необходимо изучить фактические Printer-MIB supplies
и повторить их паттерн:

```text
SNMP polling → нормализованные текущие значения → история → специализированный UI
```

Используются существующие SNMP client/service, scheduler, cleanup, backup/restore,
`IncidentService`, notifications, Target Health, SVG-графики и права доступа.

## Включение и polling

- UPS Monitoring полностью optional; default — выключен.
- Механизм включения выбирается по фактическому паттерну Printer-MIB: отдельный тип
  `ups` либо capability внутри SNMP, но не две параллельные системы.
- При выключенном UPS Monitoring дополнительные UPS OID не запрашиваются и records
  не создаются.
- UPS polling выполняется только внутри успешного существующего SNMP polling после
  успешной primary-проверки Target. Отдельного scheduler/job нет.
- Offline Target или SNMP error не создают новых UPS данных и не закрывают открытые
  UPS incidents: состояние меняется только после следующего успешного UPS polling.
- Scalar OID читаются существующим batch GET, таблицы input/output — существующим
  walk/bulk подходом. Отсутствие optional OID не делает весь UPS polling ошибочным.

## Поддерживаемый UPS-MIB

### APC PowerNet (Smart-UPS)

Если базовые scalar OID RFC 1628 не отвечают, polling тем же пакетным SNMP GET
проверяет PowerNet MIB APC. Профиль не является отдельным scheduler или новой
подсистемой: он сохраняет данные в тех же UPS state, line, sample и incident
сущностях. Для Smart-UPS предпочтительны high-precision OID с масштабом `0.1`,
а обычные PowerNet OID остаются fallback. Сохраняются и отображаются причина
последнего перехода на батарею, результат и строковая дата последнего self-test.
Нестандартный порт берётся исключительно из `SnmpConfig` объекта.

Идентификация:

- `upsIdentManufacturer` — `1.3.6.1.2.1.33.1.1.1.0`;
- `upsIdentModel` — `1.3.6.1.2.1.33.1.1.2.0`.

Батарея:

- `upsBatteryStatus` — `1.3.6.1.2.1.33.1.2.1.0`;
- `upsSecondsOnBattery` — `1.3.6.1.2.1.33.1.2.2.0`;
- `upsEstimatedMinutesRemaining` — `1.3.6.1.2.1.33.1.2.3.0`;
- `upsEstimatedChargeRemaining` — `1.3.6.1.2.1.33.1.2.4.0`;
- `upsBatteryVoltage` — `1.3.6.1.2.1.33.1.2.5.0`;
- `upsBatteryTemperature` — `1.3.6.1.2.1.33.1.2.7.0`.

Вход и выход:

- `upsInputNumLines` — `1.3.6.1.2.1.33.1.3.2.0`, input table
  `1.3.6.1.2.1.33.1.3.3.1`;
- `upsOutputSource` — `1.3.6.1.2.1.33.1.4.1.0`;
- `upsOutputFrequency` — `1.3.6.1.2.1.33.1.4.2.0`;
- `upsOutputNumLines` — `1.3.6.1.2.1.33.1.4.3.0`, output table
  `1.3.6.1.2.1.33.1.4.4.1`.

Для фаз берутся voltage, frequency, current (если есть), power (если есть) и percent
load. Метрики фаз хранятся по стабильному ключу, например `input_voltage:1` и
`output_load:3`; трёхфазное устройство не сводится искусственно к одной фазе.

Значения normalise до человеческих единиц до сохранения/display согласно фактическому
Printer-MIB pattern. Неподдерживаемые OID показываются как «Нет данных». Базовая
проверка поддержки — manufacturer, battery status и output source; возможен статус
«UPS-MIB: частично поддерживается».

Нормализация enum:

| Поле | Значения |
| --- | --- |
| `upsBatteryStatus` | 1 Неизвестно; 2 Норма; 3 Низкий заряд; 4 Батарея разряжена |
| `upsOutputSource` | 1 Другое; 2 Выход отключён; 3 От сети; 4 Bypass; 5 От батареи; 6 AVR Boost; 7 AVR Trim |

AVR Boost/Trim считаются работой от сети, но фактическое состояние показывается явно.

## Данные, история и UI

Модели current state, samples, dedup одинаковых значений, retention и cleanup должны
максимально повторить Printer Supplies. Числовая история включает заряд, автономность,
seconds-on-battery, battery voltage/temperature, входные/выходные voltage/frequency,
output load и доступные current/power. Status-значения battery/output source не должны
дублироваться каждый polling: изменение состояния сохраняется как отдельное событие.

На объекте появляется специализированный блок «ИБП»: manufacturer/model, питание,
состояние батареи, заряд, runtime, нагрузка, input и output. На трёх фазах показывается
отдельная строка на L1/L2/L3.

История следует существующему стилю Printer/SNMP, ориентировочный URL:
`/targets/<id>/snmp/ups/history`. Периоды и существующий SVG chart framework
переиспользуются; графики: заряд, автономность, нагрузка, входное и выходное
напряжение. UI обязателен для desktop/tablet/mobile без overflow.

## Incidents и Target Health

Числовые UPS thresholds не создаются: при необходимости пользователь применяет
существующие SNMP thresholds/manual OID. Логические UPS states используют текущие
`Incident` и notification pipeline с dedup одного открытого incident на состояние:

| Состояние | Severity |
| --- | --- |
| От батареи | Warning |
| Низкий заряд | Critical |
| Батарея разряжена | Critical |
| Bypass | Warning |
| Выход отключён | Critical |

Повторный одинаковый polling не создаёт новый incident/notification. Возврат к норме
создаёт обычный Recovery. UPS warning/critical участвует в существующем Target Health
без N+1: Target Online + On Battery = Warning; Low battery/Output Off = Critical;
primary Offline имеет приоритет.

## Cleanup и backup

Политика повторяет Printer-MIB:

- выключение UPS Monitoring сохраняет конфигурацию и следует существующей политике
  Printer-MIB для runtime/history;
- «Очистить SNMP данные» очищает UPS runtime/history в том же объёме, что printer data;
- удаление Target каскадно удаляет все UPS records/history;
- configuration backup хранит включение/конфигурацию, но runtime/history обрабатывает
  так же, как configuration backup Printer Supplies;
- full backup хранит UPS current state, history и incidents согласно текущей full
  semantics;
- legacy backup без UPS tables/fields восстанавливается, UPS Monitoring default OFF.

## Обязательная проверка реализации

До кода: выполнить `git status`, `alembic current`, `alembic heads`, прочитать
`AGENTS.md`, определить реальный head и создать следующую линейную migration. Не
предполагать её номер заранее.

Автоматически покрыть минимум: default OFF; обычный SNMP без UPS; supported и
partially-supported UPS-MIB; mapping battery/output states; нормализацию единиц;
одно- и трёхфазные таблицы; missing OID; current/history/dedup; logical incidents и
recovery; Offline/SNMP error не закрывают UPS incident; Target Health; configuration,
full и legacy backup; cleanup/disable/delete cascade; отсутствие N+1; responsive UI;
регрессию Printer-MIB.

QA: `ruff check .`, полный `pytest`, `python -m compileall src`, `git diff --check`,
линейная Alembic-chain, PostgreSQL migration до нового head и physical smoke при
наличии реального UPS. Если hardware нет, это должно быть честно указано в отчёте, без
имитации успешного hardware smoke.
