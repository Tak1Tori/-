# Simple command attack classifier

Минимальный baseline для классификации последовательностей команд по типу атаки.

## Что делает

- Берет набор команд и превращает его в одну строку.
- Нормализует IP-адреса, пути и длинные хеши.
- Обучает модель `TF-IDF + Logistic Regression`.
- Предсказывает один из классов:
  - `recon`
  - `db_attack`
  - `lateral_movement`
  - `priv_esc`
  - `other`

## Установка

```bash
python3 -m pip install -r requirements.txt
```

## Обучение

```bash
python3 train_model.py
```

Модель сохранится в `artifacts/command_attack_model.joblib`.

## Предсказание

```bash
python3 predict.py "whoami" "net user" "ipconfig"
python3 predict.py "sqlcmd -Q SELECT * FROM users"
python3 predict.py "psexec \\\\host cmd.exe"
```

## Формат датасета

CSV с колонками:

- `label`
- `commands`

Пример:

```csv
label,commands
recon,"whoami && net user && ipconfig"
db_attack,"sqlcmd -Q SELECT * FROM users"
```

## Что улучшать дальше

- Добавить больше реальных примеров в `data/examples.csv`.
- Балансировать классы, чтобы не было перекоса.
- Вынести предобработку аргументов в отдельный модуль.
- Сравнить с `LinearSVC` и `XGBoost`.
- Потом, если baseline упрется в потолок, попробовать `DistilBERT`.
