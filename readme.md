ДЗ 1-4 ПО ВЕБ-БЕЗОПАСНОСТИ  

HTTP/HTTPS Proxy Server with Request History API

Установка сертификатов
```bash
chmod +x gen_ca.sh
chmod +x gen_cert.sh
./gen_ca.sh
```

Запуск с Docker Compose:
```bash
docker-compose up --build
```

Это запустит:
- Прокси-сервер на портах 8080 (прокси) и 8000 (API)
- PostgreSQL базу данных для хранения запросов

Пример использования прокси c HTTP:
```bash
curl -x http://localhost:8080 http://mail.ru 
```

Пример использования прокси c HTTPS (требует установки CA сертификата):
```bash
curl -x http://127.0.0.1:8080 https://mail.ru  
curl -v -x http://127.0.0.1:8080 https://mail.ru  
```

API Эндпоинты

Получить все запросы:
```bash
curl http://localhost:8000/requests
```

Получить детали запроса:
```bash
curl http://localhost:8000/requests/1
```

Повторить запрос:
```bash
curl http://localhost:8000/repeat/1
```

Примеры использования с различными методами:
```bash
curl -X GET -x http://localhost:8080 http://httpbin.org/get

curl -X POST -x http://localhost:8080 https://mail.ru/post -d "test=data"

curl -v -X OPTIONS -x http://localhost:8080 http://httpbin.org
```

Примеры проверки статусов:
```bash
curl -v -x http://localhost:8080 http://httpbin.org/status/200

curl -v -x http://localhost:8080 http://httpbin.org/status/404

curl -v -x http://localhost:8080 http://httpbin.org/status/500
```

1. Подключение к PostgreSQL через терминал:
```bash
docker exec -it proxy-postgres-1 psql -U postgres -d proxy_db
```

2. Просмотр всех запросов:
```sql
SELECT id, request->>'method' as method, request->>'path' as path, 
       response->>'code' as status_code, timestamp, is_https 
FROM requests 
ORDER BY timestamp DESC 
LIMIT 10;
```
3. Поиск запросов по методу:
```sql
SELECT id, request->>'method' as method, request->>'path' as path, 
       response->>'code' as status_code, timestamp 
FROM requests 
WHERE request->>'method' = 'POST' 
ORDER BY timestamp DESC;
```

4. Просмотр деталей конкретного запроса:
```sql
SELECT id, request, response, timestamp, is_https 
FROM requests 
WHERE id = 1;
```

5. Статистика по кодам ответа:
```sql
SELECT response->>'code' as status_code, COUNT(*) as count 
FROM requests 
GROUP BY response->>'code' 
ORDER BY count DESC;
```

5. Очистка старых запросов (например, старше 30 дней):
```sql
DELETE FROM requests 
WHERE timestamp < NOW() - INTERVAL '30 days';
```

и т.д...

Все запросы и ответы сохраняются в PostgreSQL с детальным парсингом:
- HTTP метод
- Путь и GET параметры
- Заголовки и Cookie
- Тело запроса (включая POST параметры для application/x-www-form-urlencoded)
- Ответы с кодом, заголовками и телом
- Поддержка сжатия (gzip)

Вариант 6. Param-miner – добавить к запросу по очереди каждый GET параметр из словаря https://github.com/PortSwigger/param-miner/blob/master/resources/params со случайным значением (?param=shefuisehfuishe)
искать указанное случайное значение в ответе, если нашлось, вывести название скрытого параметра

Сканировать запрос:
```bash
curl http://localhost:8000/scan/1
```

Результат сканирования:
```json
{
  "status": "scan completed",
  "headers": {
    "Content-Type": "application/json",
    "User-Agent": "curl/7.64.1"
  },
  "hidden_params": [
    "debug",
    "admin",
    "test"
  ]
}
```

Сканер проверяет наличие скрытых параметров, добавляя каждый параметр из словаря со случайным значением и проверяя, отражается ли это значение в ответе. Если значение найдено в ответе, параметр считается активным.