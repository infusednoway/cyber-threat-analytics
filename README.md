# Прототип системы предиктивной аналитики киберугроз на основе открытых источников

Дипломная работа по направлению 10.03.01 «Информационная безопасность», Московский Политехнический Университет.

Система собирает данные об уязвимостях из открытых источников, обрабатывает их с помощью нескольких ML-моделей и отображает результаты в веб-интерфейсе с разграничением прав доступа.

---

## Что умеет система

**Сбор данных**
- CVE из NVD (NIST) через официальный API v2, до 2000 записей за 90 дней
- Публичные эксплойты с Exploit-DB (тип, платформа, CVE-привязка)
- Новости ИБ из RSS-лент: The Hacker News, BleepingComputer, CISA, Krebs on Security, Kaspersky Securelist
- MITRE ATT&CK техники и тактики через STIX-формат
- Интеграция с Shodan API для оценки экспозиции хостов (fallback на mock-данные без ключа)

**Машинное обучение**
- Классификация угроз по уровню опасности (TF-IDF + Random Forest)
- Прогноз количества CVE на 14 дней вперёд (полиномиальная регрессия)
- Детектирование аномалий в потоке CVE (z-score по скользящему окну)
- NLP-анализ описаний CVE: извлечение типов угроз, продуктов, ключевых слов
- Сравнение трёх моделей с 5-fold кросс-валидацией (LR, RF, SVM)

**Аналитика**
- Риск-скор CVE от 0 до 100 — взвешенная сумма пяти компонент: severity/CVSS, наличие эксплойта, тип угрозы, давность публикации, сигнальные слова в описании
- Экспозиция продуктов: сводка по уязвимым продуктам с разбивкой по критичности
- Статистика: распределение CVSS, топ CWE, статистика эксплойтов по платформам, источники новостей
- Отчёты: исполнительная сводка, полный отчёт, еженедельный/ежемесячный дайджест, сравнение периодов

**Алерты и уведомления**
- Автоматические алерты при аномальном росте CVE или появлении критических уязвимостей
- Три канала доставки уведомлений: in-app, e-mail (SMTP), webhook/Slack

**Интерфейс**
- Три роли: admin, analyst, viewer — с разными правами доступа
- 20+ страниц: дашборд, CVE, эксплойты, новости, алерты, прогноз, риск, экспозиция, аномалии, MITRE ATT&CK, статистика, watchlist, отчёты, модели ML, профиль, настройки, управление пользователями
- Watchlist — отслеживание конкретных CVE с пометками

---

## Стек

| Компонент | Технология |
|-----------|-----------|
| Язык | Python 3.10+ |
| База данных | SQLite |
| Веб-фреймворк | Flask + Blueprint |
| ML | scikit-learn (TF-IDF, RF, LR, SVM) |
| Данные | pandas, numpy |
| Визуализация | Chart.js 4, Bootstrap 5 |
| Внешние API | NVD API v2, Shodan API, MITRE STIX |

---

## Структура

```
├── main.py
├── requirements.txt
├── data/
│   ├── threats.db
│   ├── classifier.pkl
│   └── model_comparison.json
└── src/
    ├── collectors/
    │   ├── nvd_collector.py
    │   ├── rss_collector.py
    │   ├── exploit_collector.py
    │   ├── mitre_collector.py
    │   └── shodan_collector.py
    ├── database/
    │   └── db.py
    ├── models/
    │   ├── classifier.py
    │   ├── predictor.py
    │   ├── alerter.py
    │   ├── anomaly_detector.py
    │   ├── nlp_analyzer.py
    │   ├── risk_scorer.py
    │   └── model_comparison.py
    ├── utils/
    │   ├── statistics.py
    │   ├── report_builder.py
    │   └── notifier.py
    └── dashboard/
        ├── app.py
        ├── routes/
        │   ├── auth_routes.py
        │   ├── main_routes.py
        │   └── api_routes.py
        └── templates/
```

---

## Установка

```bash
git clone https://github.com/infusednoway/cyber-threat-analytics.git
cd cyber-threat-analytics

python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/macOS

pip install -r requirements.txt
```

Опциональные переменные окружения:

```
SHODAN_API_KEY=...   # без ключа работает на mock-данных
SMTP_HOST=...
SMTP_USER=...
SMTP_PASS=...
WEBHOOK_URL=...      # Slack incoming webhook
```

---

## Запуск

```bash
# Полный цикл: сбор → обучение → сравнение моделей → дашборд
python main.py all

# Только сбор данных
python main.py collect

# Обучение классификатора
python main.py train

# Сравнение моделей (5-fold CV)
python main.py compare

# Только дашборд (если данные уже есть)
python main.py dashboard
```

Дашборд открывается на **http://127.0.0.1:5000**

Дефолтный аккаунт администратора создаётся при первом запуске: `admin` / `admin123`

---

## API

Основные эндпоинты (полный список в `src/dashboard/routes/api_routes.py`):

| Эндпоинт | Описание |
|----------|----------|
| `GET /api/summary` | Общая статистика |
| `GET /api/timeline` | Временной ряд + прогноз на 14 дней |
| `GET /api/alerts` | Текущие алерты |
| `GET /api/cves` | CVE с фильтрацией |
| `GET /api/exploits` | Эксплойты |
| `GET /api/risk/top` | Топ CVE по риск-скору |
| `GET /api/risk/distribution` | Распределение риск-уровней |
| `GET /api/risk/explain/<cve_id>` | Объяснение скора конкретной CVE |
| `GET /api/nlp/threat_distribution` | Типы угроз по NLP-анализу |
| `GET /api/nlp/product_exposure` | Уязвимые продукты |
| `GET /api/shodan/exposure/<cve_id>` | Экспозиция CVE по Shodan |
| `GET /api/anomalies` | Обнаруженные аномалии |
| `GET /api/report/executive` | Исполнительная сводка |
| `GET /api/report/weekly` | Еженедельный дайджест |

---

## Источники данных

| Источник | Данные |
|----------|--------|
| NVD / NIST | CVE, CVSS, CWE |
| Exploit-DB | Публичные эксплойты |
| MITRE ATT&CK | Тактики и техники (STIX) |
| Shodan | Экспозиция хостов |
| The Hacker News, BleepingComputer, CISA, Krebs on Security, Kaspersky Securelist | Новости ИБ |

---

## Требования

- Python 3.10+
- ~300 МБ свободного места
- Интернет для сбора данных
