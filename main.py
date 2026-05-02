"""
Прототип системы предиктивной аналитики киберугроз
на основе открытых источников.

Использование:
    python main.py collect    -- сбор данных (NVD + RSS + Exploit-DB)
    python main.py train      -- обучение модели классификации
    python main.py compare    -- сравнение моделей (5-fold CV)
    python main.py dashboard  -- запуск веб-дашборда
    python main.py all        -- всё сразу (по умолчанию)
"""

import sys

from src.database.db import init_db


def cmd_collect():
    from src.collectors.nvd_collector import fetch_cves
    from src.collectors.rss_collector import fetch_news
    from src.collectors.exploit_collector import fetch_exploits

    print("=== Сбор данных ===")
    init_db()
    fetch_cves(days_back=90, max_results=2000)
    fetch_news()
    fetch_exploits()
    print("Сбор завершён.\n")


def cmd_train():
    from src.models.classifier import train

    print("=== Обучение модели ===")
    model = train()
    if model:
        print("Модель обучена успешно.\n")
    else:
        print("Обучение не выполнено: недостаточно данных.\n")


def cmd_compare():
    from src.models.model_comparison import run_comparison

    print("=== Сравнение моделей (5-fold кросс-валидация) ===")
    results = run_comparison()
    if results:
        print(f"\n{'Модель':<30} {'Точность':>9} {'F1':>8} {'Precision':>10} {'Recall':>8}")
        print("-" * 68)
        for r in results:
            print(f"{r['model']:<30} {r['accuracy']:>9.4f} {r['f1']:>8.4f} {r['precision']:>10.4f} {r['recall']:>8.4f}")
    print()


def cmd_dashboard():
    from src.dashboard.app import run

    print("=== Запуск дашборда ===")
    print("Откройте в браузере: http://127.0.0.1:5000")
    run(debug=False)


COMMANDS = {
    "collect":   cmd_collect,
    "train":     cmd_train,
    "compare":   cmd_compare,
    "dashboard": cmd_dashboard,
}


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"

    if cmd == "all":
        init_db()
        cmd_collect()
        cmd_train()
        cmd_compare()
        cmd_dashboard()
    elif cmd in COMMANDS:
        init_db()
        COMMANDS[cmd]()
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
