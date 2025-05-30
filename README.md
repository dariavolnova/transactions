# Blockchain Transaction Implementation

Реализация транзакции для блокчейна с поддержкой:
- Множественных входов/выходов
- Цифровых подписей ECDSA
- Сериализации/десериализации


## Установка
1. Склонируйте репозиторий
```bash
git clone https://github.com/dariavolnova/transactions
```

2. Установите зависимости
```bash
pip install cryptography
```

## Использование
Пример создания транзакции:

```python
from transaction import Transaction, TransactionInput, TransactionOutput
from cryptography.hazmat.primitives.asymmetric import ec

#Генерация ключей
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

#Создание транзакции
tx = Transaction()
tx.add_input(TransactionInput("prev_tx_id", 0))
tx.add_output(TransactionOutput(10.0, hashlib.sha256(public_key.public_bytes()).digest()))

#Подпись
tx.sign_input(0, private_key)

#Проверка
print("Transaction valid:", tx.verify())
```

## Тестирование
Запуск тестов:

```bash
python -m unittest test_transaction.py
```

Тесты проверяют:

- Базовую функциональность транзакций

- Механизм подписи и верификации

- Сериализацию/десериализацию

- Граничные случаи
