ДЗ 1-2 ПО ВЕБ-БЕЗОПАСНОСТИ  

HTTP/HTTPS Proxy Server with Request History API

Установка сертификатов
```bash
chmod +x gen_ca.sh
chmod +x gen_cert.sh
./gen_ca.sh
```
Сборка Docker-образа:
```bash
docker build -t proxy-server .
```

Запуск Docker-контейнера:
```bash
docker run -p 8080:8080 -p 8000:8000 -v $(pwd)/certs:/app/certs proxy-server
```


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

Получить все запросы :
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

Сканировать запрос:
```bash
curl http://localhost:8000/scan/1
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

