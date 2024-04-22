import socket
from socket import timeout
import sys
import re

udp_port = 34434  # По умолчанию запрос отправляется на закрытый порт 34434.
ttl = 30  # разумный" time to live
local_host = ""  # адрес


def main():
    address = sys.argv[1]  # считывает название сайта
    traceroute(address)  # запускаем веселье


def whois(address_marshrutizatora):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        who = socket.gethostbyname("whois.iana.org")
        s.connect((who, 43))  # обращаемся к whois (43 порт)
        s.send((address_marshrutizatora + "\r\n").encode())
        message = b""
        while True:
            stroka = s.recv(2024)
            message += stroka  # считывание сообщения (по 2024 байта)
            if stroka == b"":
                break

        message = message.decode()
        whois_server = ''
        for line in message.split('\n'):
            if 'refer' in line.lower():
                whois_server = line.split()[-1]

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock_second:
            sock_second.connect((whois_server, 43))
            sock_second.send((address_marshrutizatora + "\r\n").encode())
            response2 = b""
            while True:
                response2 += sock_second.recv(2024)
                if not sock_second.recv(2024):
                    break
            message2 = response2.decode()
        return (f"  {whois_netname(message2)} {whois_origin(message2)} {whois_country(message2)} \r\n")


def whois_netname(message2):  # имя сети
    netname = re.findall(r"(netname:\s+\w+)", message2)
    if netname != []:
        str = netname[0]
        spstr = str.split()
        output = ''.join(spstr[1:])
        return output
    else:
        return ""


def whois_country(message2):  # название страны
    country = re.findall(r"country:\s+\w+", message2)

    if country != []:
        str = country[0]
        spstr = str.split()
        if spstr[-1] == 'EU':
            address = re.findall(r"address:\s+\w+", message2)
            str = address[-1]
            spstr = str.split()
            output = ''.join(spstr[1:])
            return output
        output = ''.join(spstr[1:])
        return output
    else:
        return ""


def whois_origin(message2):  # номер автономной системы
    origin = re.findall(r"origin:\s+\w+", message2)
    if origin != []:
        str = origin[0]
        spstr = str.split()
        output = ''.join(spstr[1:])
        return output
    else:
        return ""


def ip_local(address_marshrutizatora):
    octets = [int(x) for x in address_marshrutizatora.split('.')]
    if octets[0] == 10:
        return 'local'
    if octets[0] == 192 and octets[1] == 168:
        return 'local'
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return 'local'
    return 'no local'


def traceroute(address):
    host = ''
    try:
        host = socket.gethostbyname(
            address)  # Преобразует имя хоста в формат адреса IPv4. Адрес IPv4 возвращается в виде строки, например '100.50.200.5'.
    except:
        print(address, " is invalid")
        exit()
    if host == '127.0.0.1':
        print('sorry, goodbye')
        exit()
    if ip_local(host) == 'local':  # проверяем на локальность
        output = "  " + ip_local(host) + "\r\n"
        print(ip_local(host), "\r\n")
        exit()
    TTl = 1
    f = 0
    address_marshrutizatora = ""  # хранение адресов роутеров (промежуточное ip)
    # Первый пакет отправляется с TTL=1, второй с TTL=2 и так далее, пока запрос не попадет адресату.
    while ((TTl < ttl) and (address_marshrutizatora != host)):
        # настраиваем udp сокет
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                   socket.IPPROTO_UDP)  # socket.AF_INET семейство адресов - ipV4 socket.SOCK_DGRAM - тип сокета по отправляемому сообщению (ДЕЙТАГРАММА) socket.IPPROTO_UDP - номер протокола (конст = 17)
        udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL,
                              TTl)  # SOL_IP - настроить функции ip пакета https://stackoverflow.com/questions/72319941/what-do-socket-sol-socket-and-socket-so-reuseaddr-in-python, что настраиваем (ттл) и само значение
        udp_socket.sendto('qq'.encode(), (host,
                                          udp_port))  # Send data to the socket. The socket should not be connected to a remote socket, since the destination socket is specified by address. The optional flags argument has the same meaning as for recv() above. Return the number of bytes sent. (The format of address depends on the address family — see above.)   ---- (host, port) - is used for the AF_INET address family, where host is a string representing either a hostname in internet domain notation
        # Отправить данные в сокет. Сокет не должен быть подключен к удаленному сокету, поскольку целевой сокет указан по адресу. Необязательный аргумент flags имеет то же значение, что и для recv() выше. Возвращает количество отправленных байт. (Формат адреса зависит от семейства адресов — смотрите выше.) ---- (хост, порт) - используется для семейства адресов AF_INET, где host - это строка, представляющая либо имя хоста в обозначениях домена Интернета
        # настраиваем icmp сокет
        # ожидает ответа о недоступности этого порта.  Когда запрос попадёт на хост назначения, этот хост отправит ответ о недоступности порта «Destination port unreachable» (порт назначения недоступен).
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                    socket.IPPROTO_ICMP)  # class socket.socket(family=AF_INET, type=SOCK_STREAM, proto=0, fileno=None)    SOCK_RAW - режим управления сокетом  Когда запрос попадёт на хост назначения, этот хост отправит ответ о недоступности порта «Destination port unreachable» (порт назначения недоступен).я
        icmp_socket.bind((local_host,
                          udp_port))  # Привязать сокет к адресу. Сокет не должен быть уже привязан. один аргумент = пара (,) По умолчанию запрос отправляется на закрытый порт 34434
        icmp_socket.settimeout(2)  # настраиваем время ожидания (от изменения значения не изменяется результат!)

        try:
            a = icmp_socket.recvfrom(2024)  # считали 2024 байтиков
            address_marshrutizatora = a[1][0]  # достали роутер ~ маршрутизатор
            print(f"{TTl}. {address_marshrutizatora}")
            if ip_local(address_marshrutizatora) == 'local':  # проверяем на локальность
                print("   ", ip_local(address_marshrutizatora), "\r\n")
            else:
                print(whois(address_marshrutizatora))  # не локальный - выводим нужную инфу


        except timeout:
            print(f"{TTl}. **\r\n")  # мы можем ничепго не получитьь
        TTl += 1


if __name__ == "__main__":
    main()

# self.setsockopt(IPPROTO_UDPLITE, UDPLITE_SEND_CSCOV, length) настройки сокета
# Утилита Traceroute вместо ICMP-запроса отправляет 1 UDP-пакет на определенный порт целевого хоста и ожидает ответа о недоступности этого порта.
#  Первый пакет отправляется с TTL=1, второй с TTL=2 и так далее, пока запрос не попадет адресату.
# Отличие от Tracert в том, как Traceroute понимает, что трассировка завершена.
# Так как вместо ICMP-запроса он отправляет UDP-запрос, в каждом запросе есть порт отправителя (Sourсe) и порт получателя (Destination).
# По умолчанию запрос отправляется на закрытый порт 34434.
#  Когда запрос попадёт на хост назначения, этот хост отправит ответ о недоступности порта «Destination port unreachable» (порт назначения недоступен).
# Это значит, что адресат получил запрос. Traceroute воспримет этот ответ как завершение трассировки.

# cd /Users/mac/Downloads
# sudo python3 my.py
# 45.236.171.77 - Южная Америка
# msu.ru
# 192.168.0.1 - локальный
# 139.99.237.62 - Австралия
# 8474737364oskdk инвалидный адрес
# 127.0.0.1 - да.