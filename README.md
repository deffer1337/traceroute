# traceroute
### Описание.

Свой traceroute с возможностью отправки пакетов по ICMP, TCP или UDP.

Утилита должна запускаться следующим образом:

```
traceroute [OPTIONS] IP_ADDRESS {tcp|udp|icmp}
```

Опции `[OPTIONS]` должны быть следующие:

* `-t` — таймаут ожидания ответа (по умолчанию 2с)
* '-p' — порт (для tcp или udp)
* '-n' — максимальное количество запросов
* `-v` — вывод номера автономной системы для каждого ip-адреса

Пример запуска:
```
traceroute -p 53 1.1.1.1 tcp
```
