```markdown
# File server (локальная сеть)

Небольшой HTTP/HTTPS/FTP файловый сервер для локальной сети с простым клиентом, веб-интерфейсом и GUI для управления.

Ключевые возможности
- Листинг, загрузка (multipart/form-data), скачивание (поддержка Range), удаление файлов
- Простая аутентификация по токену (X-Auth-Token или ?token=) и HTTP Basic
- Ограничение доступа только папкой `data` рядом со скриптом
- Поддержка HTTPS (локальные сертификаты или реальный CA)
- Поддержка FTP протокола для совместимости с FTP-клиентами
- GUI для удобного конфигурирования и запуска сервера с логами в реальном времени

Требования
- Python 3.8+
- Установить зависимости:

```bash
pip install -r requirements.txt
```

Поведение по умолчанию
- Сервер обслуживает папку `data` рядом с `file_server.py`. Папка создаётся автоматически, если её нет.
- Доступ ограничен этой папкой — попытки указать `--dir` за её пределами будут проигнорированы и сервер будет использовать `./data`.

Запуск сервера

```bash
python3 file_server.py --host 0.0.0.0 --port 8080 --token mysecret
```

Аргументы (самое важное)
- --host — адрес для биндинга (по умолчанию 0.0.0.0)
- --port — порт (по умолчанию 8080)
- --dir — каталог для хранения файлов (по умолчанию `data` рядом со скриптом). Относительные пути считаются относительно каталога скрипта.
- --token — простой токен для аутентификации (опционально)
- --basic-user / --basic-pass — username и password для HTTP Basic (опционально)
- --tls — (legacy) включить HTTPS (устаревающий флаг, сохранён для совместимости)
- --protocol — новый аргумент: `http`, `https` или `ftp`. Если указан, имеет приоритет над `--tls`.
- --cert/--key — пути к файлам сертификата и приватного ключа (PEM)
- --generate-self-signed — сгенерировать временный самоподписанный сертификат (требует openssl)

API
- GET /files — возвращает JSON со списком файлов
- GET /download/{path} — скачать файл
- POST /upload — multipart/form-data (поле `file`)
- DELETE /delete/{path} — удалить файл

Примеры клиента

Загрузить файл:
```bash
python3 client.py upload http://localhost:8080 ./myfile.txt --token mysecret
```

Скачать файл:
```bash
python3 client.py download http://localhost:8080 some/path.txt ./out.txt --token mysecret
```

HTTPS (коротко)

Вы можете запустить сервер по HTTPS. Приоритет выбора TLS:
1. Если задан `--protocol https` — сервер попытается запуститься по HTTPS.
2. Если `--protocol` не указан, но указан `--tls` — включается HTTPS (legacy поведение).

Примеры запуска по HTTPS:
```bash
# Использовать готовые cert/key
python3 file_server.py --protocol https --cert ./certs/server.crt --key ./certs/server.key --host 0.0.0.0 --port 8443 --token mysecret

# Сгенерировать временный самоподписанный
python3 file_server.py --protocol https --generate-self-signed --host 0.0.0.0 --port 8443 --token mysecret

# Старый стиль (если protocol не указан)
python3 file_server.py --tls --cert ./certs/server.crt --key ./certs/server.key
```

Как убрать предупреждения браузера (сертификат, доверенный клиентом)

1) Let's Encrypt (публичный домен)
    - Требования: публичный домен, порт 80 доступен или DNS-01 challenge.
    - В репозитории есть скрипт `obtain_cert_lets_encrypt.sh` для получения certbot-сертификата и копирования его в `./certs/<domain>/`.

2) mkcert (лучший вариант для LAN / разработки)
    - Установите `mkcert` на машину, где будете генерировать сертификат: https://github.com/FiloSottile/mkcert
    - Выполните `mkcert -install` чтобы установить локальную CA в систему.
    - Сгенерируйте сертификат для нужных имён/IP, например:
```bash
mkdir -p certs
mkcert -cert-file certs/server.crt -key-file certs/server.key "file-server.local" "192.168.1.42"
```
    - Скопируйте `rootCA.pem` в клиентские машины и установите его как доверенный (или запустите `mkcert -install` на каждом клиенте).

3) Собственный локальный CA (openssl)
    - Можно создать root CA и подписать серверный CSR вручную. Нужна ручная установка root CA на всех клиентах.

Проверка в браузере и командной строке
- Откройте https://<host>:<port>/ui/ в браузере. Если сертификат доверенный — предупреждений не будет.
- curl с указанием доверенного CA (для тестирования):
```bash
curl --cacert ./path/to/rootCA.pem https://file-server.local:8443/
```

Полезные советы
- Для LAN разработки рекомендую mkcert: быстро и удобно, требует лишь импорта локальной CA на клиентских устройствах.
- Для публичного сервера используйте Let's Encrypt и автоматическое обновление (`certbot renew`).


---

Наглядные примеры и объяснение параметров
=========================================

Ниже — набор типичных сценариев с командами и пояснениями, чтобы быстро начать.

1) Быстрый запуск по HTTP (локальная сеть, без шифрования)

```bash
python3 file_server.py --protocol http --host 0.0.0.0 --port 8080 --token mysecret
```

Пояснение:
- `--protocol http` — явный выбор HTTP (альтернатива: не указывать `--protocol` и не использовать `--tls`).
- `--host 0.0.0.0` — слушать на всех интерфейсах локального хоста (доступно в LAN).
- `--port 8080` — порт для HTTP.
- `--token mysecret` — простой токен аутентификации; запросы должны содержать заголовок `X-Auth-Token: mysecret` или `?token=mysecret`.

2) HTTPS с самоподписанным сертификатом (быстро, для тестов)

```bash
python3 file_server.py --protocol https --generate-self-signed --host 0.0.0.0 --port 8443 --token mysecret
```

Пояснение:
- `--generate-self-signed` — скрипт сгенерирует временный сертификат через `openssl`. Браузер покажет предупреждение о недоверенном сертификате.
- Используйте этот режим для отладки или если вы готовы принять предупреждение в браузере.

3) HTTPS (LAN) без предупреждений — mkcert (рекомендуется для разработки в LAN)

Генерация (на машине, где будет генерироваться сертификат):

```bash
# Сначала установите mkcert и выполните mkcert -install
mkdir -p certs
mkcert -cert-file certs/server.crt -key-file certs/server.key "file-server.local" "192.168.1.42"
```

Запуск сервера:

```bash
python3 file_server.py --protocol https --cert ./certs/server.crt --key ./certs/server.key --host 0.0.0.0 --port 443 --token mysecret
```

Пояснение:
- `mkcert -install` создаёт локальную CA и устанавливает её в доверенные в ОС/браузере (на той машине, где выполнена команда). Для того чтобы другие клиентские машины доверяли сертификату, либо запустите `mkcert -install` и там, либо экспортируйте `rootCA.pem` и импортируйте его в хранилище доверенных корней на клиентских машинах.
- После установки root CA предупреждения в браузере больше не будет.

4) HTTPS для публичного домена — Let's Encrypt

```bash
./obtain_cert_lets_encrypt.sh -d your.domain.tld -m admin@your.domain -w ./static
# затем
python3 file_server.py --protocol https --cert ./certs/your.domain.tld/fullchain.pem --key ./certs/your.domain.tld/privkey.pem --host 0.0.0.0 --port 443 --token mysecret
```

Пояснение:
- Let's Encrypt выдаёт сертификат, которому доверяют все браузеры — без предупреждений.
- Требуется: публичное доменное имя, корректные DNS-записи и доступный challenge (обычно порт 80) или DNS-01.
- Скрипт `obtain_cert_lets_encrypt.sh` использует `certbot` и webroot; при ошибке проверьте лог `/var/log/letsencrypt/letsencrypt.log`.

5) Примеры клиентов (curl)

GET список файлов (curl):

```bash
curl -H "X-Auth-Token: mysecret" http://localhost:8080/files
```

Загрузка файла (curl POST multipart):

```bash
curl -H "X-Auth-Token: mysecret" -F "file=@./localfile.txt" http://localhost:8080/upload
```

Скачивание файла (curl):

```bash
curl -H "X-Auth-Token: mysecret" -o out.txt "http://localhost:8080/download/subdir/file.txt"
```

Удаление файла (curl):

```bash
curl -X DELETE -H "X-Auth-Token: mysecret" "http://localhost:8080/delete/subdir/file.txt"
```

6) Разъяснение ключевых параметров CLI

- `--protocol` — выбирает протокол запуска: `http` или `https`. Имеет приоритет над `--tls`.
- `--tls` — устаревший флаг включения HTTPS. Оставлен для обратной совместимости; если `--protocol` указан, то `--protocol` управляет выбором.
- `--cert` и `--key` — файлы сертификата и приватного ключа в PEM-формате (используются при HTTPS).
- `--generate-self-signed` — быстро создаёт временный самоподписанный сертификат (для тестирования).
- `--token` — простой строковый токен; если указан, сервер требует `X-Auth-Token` в заголовке или `?token=` в URL.
- `--dir` — каталог для хранения файлов; по умолчанию `./data` рядом со скриптом; абсолютные пути вне `./data` будут проигнорированы.
- `--host` / `--port` — адрес и порт для биндинга сервера.

Basic auth — примеры

Запуск сервера с HTTP Basic (альтернатива токену):
```bash
python3 file_server.py --protocol http --host 0.0.0.0 --port 8080 --basic-user alice --basic-pass s3cr3t
```

curl-примеры с Basic Authorization:
```bash
# список файлов
curl -H "Authorization: Basic $(echo -n 'alice:s3cr3t' | base64)" http://localhost:8080/files

# загрузка
curl -H "Authorization: Basic $(echo -n 'alice:s3cr3t' | base64)" -F "file=@./localfile.txt" http://localhost:8080/upload
```

Комбинации токена и Basic
- Сервер принимает либо валидный токен (X-Auth-Token / ?token=), либо корректные Basic credentials. Можно настроить оба одновременно; клиент отправляет нужный заголовок.

Готовые примеры запусков сервера
--------------------------------

- HTTP, без аутентификации (для временного теста):
```bash
python3 file_server.py --protocol http --host 0.0.0.0 --port 8080
```

- HTTP + токен:
```bash
python3 file_server.py --protocol http --host 0.0.0.0 --port 8080 --token mysecret
```

- HTTP + Basic auth:
```bash
python3 file_server.py --protocol http --host 0.0.0.0 --port 8080 --basic-user alice --basic-pass s3cr3t
```

- HTTPS (self-signed) + token:
```bash
python3 file_server.py --protocol https --generate-self-signed --host 0.0.0.0 --port 8443 --token mysecret
```

- HTTPS (mkcert) + Basic auth:
```bash
# сгенерировать certs/server.crt и certs/server.key через mkcert
python3 file_server.py --protocol https --cert ./certs/server.crt --key ./certs/server.key --host 0.0.0.0 --port 443 --basic-user alice --basic-pass s3cr3t
```

Как настроить сервер и клиентов чтобы НЕ было предупреждений в браузере (чеклист)
--------------------------------------------------------------------------
1) Выберите метод получения доверенного сертификата:
   - Для публичного домена: Let's Encrypt (автоматически доверяется браузерами).
   - Для локальной сети: mkcert (создаёт локальную CA и подписывает сертификат).

2) Получите сертификат и ключ и поместите их в `./certs` или указанный путь.

3) Убедитесь, что клиенты доверяют CA:
   - Для Let's Encrypt ничего делать не нужно — браузеры доверяют CA.
   - Для mkcert: на каждой клиентской машине выполните `mkcert -install` или импортируйте `rootCA.pem` в доверенные корневые сертификаты.

4) Проверьте, что URL, который вы открываете в браузере, совпадает с SAN сертификата (hostname или IP).

5) Проверьте сетевые правила: порт 443 (или указанный) должен быть доступен клиентам; если пробрасываете через NAT — настройте проброс портов и DNS.

6) Тестирование:
```bash
curl -v --cacert ./path/to/rootCA.pem https://file-server.local:443/ui/
```

---


```
# File server (локальная сеть)

Небольшой HTTP/HTTPS файловый сервер для локальной сети с простым клиентом и веб-интерфейсом.

Ключевые возможности
- Листинг, загрузка (multipart/form-data), скачивание (поддержка Range), удаление файлов
- Простая аутентификация по токену (X-Auth-Token или ?token=)
- Ограничение доступа только папкой `data` рядом со скриптом
- Поддержка HTTPS (локальные сертификаты или реальный CA)

Требования
- Python 3.8+
- Установить зависимости:

```bash
pip install -r requirements.txt
```

Поведение по умолчанию
- Сервер обслуживает папку `data` рядом с `file_server.py`. Папка создаётся автоматически, если её нет.
- Доступ ограничен этой папкой — попытки указать `--dir` за её пределами будут проигнорированы и сервер будет использовать `./data`.

Запуск сервера

```bash
python3 file_server.py --host 0.0.0.0 --port 8080 --token mysecret
```

Аргументы (самое важное)
- --host — адрес для биндинга (по умолчанию 0.0.0.0)
- --port — порт (по умолчанию 8080)
- --dir — каталог для хранения файлов (по умолчанию `data` рядом со скриптом). Относительные пути считаются относительно каталога скрипта.
- --token — простой токен для аутентификации (опционально)
- --tls — (legacy) включить HTTPS (устаревающий флаг, сохранён для совместимости)
- --protocol — новый аргумент: `http` или `https`. Если указан, имеет приоритет над `--tls`.
- --cert/--key — пути к файлам сертификата и приватного ключа (PEM)
- --generate-self-signed — сгенерировать временный самоподписанный сертификат (требует openssl)

API
- GET /files — возвращает JSON со списком файлов
- GET /download/{path} — скачать файл
- POST /upload — multipart/form-data (поле `file`)
- DELETE /delete/{path} — удалить файл

Примеры клиента

Загрузить файл:
```bash
python3 client.py upload http://localhost:8080 ./myfile.txt --token mysecret
```

Скачать файл:
```bash
python3 client.py download http://localhost:8080 some/path.txt ./out.txt --token mysecret
```

HTTPS (коротко)

Вы можете запустить сервер по HTTPS. Приоритет выбора TLS:
1. Если задан `--protocol https` — сервер попытается запуститься по HTTPS.
2. Если `--protocol` не указан, но указан `--tls` — включается HTTPS (legacy поведение).

Примеры запуска по HTTPS:
```bash
# Использовать готовые cert/key
python3 file_server.py --protocol https --cert ./certs/server.crt --key ./certs/server.key --host 0.0.0.0 --port 8443 --token mysecret

# Сгенерировать временный самоподписанный
python3 file_server.py --protocol https --generate-self-signed --host 0.0.0.0 --port 8443 --token mysecret

# Старый стиль (если protocol не указан)
python3 file_server.py --tls --cert ./certs/server.crt --key ./certs/server.key
```

Как убрать предупреждения браузера (сертификат, доверенный клиентом)

1) Let's Encrypt (публичный домен)
	- Требования: публичный домен, порт 80 доступен или DNS-01 challenge.
	- В репозитории есть скрипт `obtain_cert_lets_encrypt.sh` для получения certbot-сертификата и копирования его в `./certs/<domain>/`.

2) mkcert (лучший вариант для LAN / разработки)
	- Установите `mkcert` на машину, где будете генерировать сертификат: https://github.com/FiloSottile/mkcert
	- Выполните `mkcert -install` чтобы установить локальную CA в систему.
	- Сгенерируйте сертификат для нужных имён/IP, например:
```bash
mkdir -p certs
mkcert -cert-file certs/server.crt -key-file certs/server.key "file-server.local" "192.168.1.42"
```
	- Скопируйте `rootCA.pem` в клиентские машины и установите его как доверенный (или запустите `mkcert -install` на каждом клиенте).

3) Собственный локальный CA (openssl)
	- Можно создать root CA и подписать серверный CSR вручную. Нужна ручная установка root CA на всех клиентах.

Проверка в браузере и командной строке
- Откройте https://<host>:<port>/ui/ в браузере. Если сертификат доверенный — предупреждений не будет.
- curl с указанием доверенного CA (для тестирования):
```bash
curl --cacert ./path/to/rootCA.pem https://file-server.local:8443/
```

Полезные советы
- Для LAN разработки рекомендую mkcert: быстро и удобно, требует лишь импорта локальной CA на клиентских устройствах.
- Для публичного сервера используйте Let's Encrypt и автоматическое обновление (`certbot renew`).


---

Наглядные примеры и объяснение параметров
=========================================

Ниже — набор типичных сценариев с командами и пояснениями, чтобы быстро начать.

1) Быстрый запуск по HTTP (локальная сеть, без шифрования)

```bash
python3 file_server.py --protocol http --host 0.0.0.0 --port 8080 --token mysecret
```

Пояснение:
- `--protocol http` — явный выбор HTTP (альтернатива: не указывать `--protocol` и не использовать `--tls`).
- `--host 0.0.0.0` — слушать на всех интерфейсах локального хоста (доступно в LAN).
- `--port 8080` — порт для HTTP.
- `--token mysecret` — простой токен аутентификации; запросы должны содержать заголовок `X-Auth-Token: mysecret` или `?token=mysecret`.

2) HTTPS с самоподписанным сертификатом (быстро, для тестов)

```bash
python3 file_server.py --protocol https --generate-self-signed --host 0.0.0.0 --port 8443 --token mysecret
```

Пояснение:
- `--generate-self-signed` — скрипт сгенерирует временный сертификат через `openssl`. Браузер покажет предупреждение о недоверенном сертификате.
- Используйте этот режим для отладки или если вы готовы принять предупреждение в браузере.

3) HTTPS (LAN) без предупреждений — mkcert (рекомендуется для разработки в LAN)

Генерация (на машине, где будет генерироваться сертификат):

```bash
# Сначала установите mkcert и выполните mkcert -install
mkdir -p certs
mkcert -cert-file certs/server.crt -key-file certs/server.key "file-server.local" "192.168.1.42"
```

Запуск сервера:

```bash
python3 file_server.py --protocol https --cert ./certs/server.crt --key ./certs/server.key --host 0.0.0.0 --port 443 --token mysecret
```

Пояснение:
- `mkcert -install` создаёт локальную CA и устанавливает её в доверенные в ОС/браузере (на той машине, где выполнена команда). Для того чтобы другие клиентские машины доверяли сертификату, либо запустите `mkcert -install` и там, либо экспортируйте `rootCA.pem` и импортируйте его в хранилище доверенных корней на клиентских машинах.
- После установки root CA предупреждения в браузере больше не будет.

4) HTTPS для публичного домена — Let's Encrypt

```bash
./obtain_cert_lets_encrypt.sh -d your.domain.tld -m admin@your.domain -w ./static
# затем
python3 file_server.py --protocol https --cert ./certs/your.domain.tld/fullchain.pem --key ./certs/your.domain.tld/privkey.pem --host 0.0.0.0 --port 443 --token mysecret
```

Пояснение:
- Let's Encrypt выдаёт сертификат, которому доверяют все браузеры — без предупреждений.
- Требуется: публичное доменное имя, корректные DNS-записи и доступный challenge (обычно порт 80) или DNS-01.
- Скрипт `obtain_cert_lets_encrypt.sh` использует `certbot` и webroot; при ошибке проверьте лог `/var/log/letsencrypt/letsencrypt.log`.

5) Примеры клиентов (curl)

GET список файлов (curl):

```bash
curl -H "X-Auth-Token: mysecret" http://localhost:8080/files
```

Загрузка файла (curl POST multipart):

```bash
curl -H "X-Auth-Token: mysecret" -F "file=@./localfile.txt" http://localhost:8080/upload
```

Скачивание файла (curl):

```bash
curl -H "X-Auth-Token: mysecret" -o out.txt "http://localhost:8080/download/subdir/file.txt"
```

Удаление файла (curl):

```bash
curl -X DELETE -H "X-Auth-Token: mysecret" "http://localhost:8080/delete/subdir/file.txt"
```

6) Разъяснение ключевых параметров CLI

- `--protocol` — выбирает протокол запуска: `http` или `https`. Имеет приоритет над `--tls`.
- `--tls` — устаревший флаг включения HTTPS. Оставлен для обратной совместимости; если `--protocol` указан, то `--protocol` управляет выбором.
- `--cert` и `--key` — файлы сертификата и приватного ключа в PEM-формате (используются при HTTPS).
- `--generate-self-signed` — быстро создаёт временный самоподписанный сертификат (для тестирования).
- `--token` — простой строковый токен; если указан, сервер требует `X-Auth-Token` в заголовке или `?token=` в URL.
- `--dir` — каталог для хранения файлов; по умолчанию `./data` рядом со скриптом; абсолютные пути вне `./data` будут проигнорированы.
- `--host` / `--port` — адрес и порт для биндинга сервера.

Пример:

вместе https

python3 file_server.py \
  --protocol https \
  --cert ./certs/server.crt \
  --key ./certs/server.key \
  --host 0.0.0.0 \
  --port 443 \
  --basic-user alice \
  --basic-pass s3cr3t \
  --token mytoken123

вместе http

python3 file_server.py \
  --protocol http \
  --host 0.0.0.0 \
  --port 8080 \
  --basic-user alice \
  --basic-pass s3cr3t \
  --token mytoken123

# FTP с токеном
python3 file_server.py --protocol ftp --host 0.0.0.0 --port 21 --token mysecret

# FTP с базовой аутентификацией
python3 file_server.py --protocol ftp --host 0.0.0.0 --port 21 --basic-user alice --basic-pass s3cr3t

# FTP без паролей(Чисто для тестов, для серьезных задач не использовать!!)
python3 file_server.py --protocol ftp --host 0.0.0.0 --port 21

## GUI для сервера

Теперь доступен графический интерфейс для управления сервером на базе CustomTkinter. GUI позволяет легко конфигурировать и запускать сервер без командной строки, с отображением логов в реальном времени.

### Запуск GUI

```bash
python3 server_gui.py
```

### Запуск GUI клиента

```bash
python3 client.py gui
```


### Установка зависимостей

GUI использует CustomTkinter. Установите его:

```bash
pip install customtkinter
```

На Linux также может потребоваться tkinter:

Debian/Ubuntu:
```bash
sudo apt install python3-tk
```

Fedora:
```bash
sudo dnf install python3-tkinter
```

На Windows/macOS tkinter обычно включён в Python.

### Функции GUI

- **Настройки сервера**: Хост, порт, директория, протокол (http/https/ftp).
- **Аутентификация**: Токен, Basic auth (пользователь/пароль).
- **TLS настройки**: Пути к сертификату и ключу, генерация самоподписанного сертификата.
- **FTP настройки**: Разрешение анонимного доступа, разрешения (read/write/full).
- **Действия**: Запуск/остановка сервера, сохранение конфигурации.
- **Логи**: Реальное время отображение вывода сервера.

Конфигурация сохраняется в `server_gui_config.json` для удобства.
И еще перед тем как запускать сервер убедитесь что у вас открыт порт который используеться, иначе он работать не будет.
