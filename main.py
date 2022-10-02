import sys
from flask import render_template as render
from flask import *
import scapy.all as scapy
import socket
import requests
from pythonping import ping

api_url = "https://api.macvendors.com/"

list_of_ports = [21, 22, 80, 8080, 443]


# czytanie listy producentów
def read_vendor_list():
    vendor_list = []
    with open("mac-vendor.txt", encoding='cp850') as my_file:
        for line in my_file:
            vendor_list.append(line.split(maxsplit=1))
    return vendor_list


def search_vendor(mac, vendor_list):
    value = mac.split(":")
    s_mac = ""
    i = 0
    vendor = ""
    for v in value:
        s_mac = s_mac + v
    s_mac = s_mac[0] + s_mac[1] + s_mac[2] + s_mac[3] + s_mac[4] + s_mac[5]
    for v in vendor_list:
        if v[0].casefold() == s_mac.casefold():
            vendor = v[1].strip()
            break
    return vendor


# Skanowanie
def scan(ip, vendor_list):
    arp_req_frame = scapy.ARP(pdst=ip)

    broadcast_ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

    answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout=1, verbose=False)[0]
    result = []
    for i in range(0, len(answered_list)):
        client_dict = {"ip": answered_list[i][1].psrc, "mac": answered_list[i][1].hwsrc,
                       "vendor": search_vendor(answered_list[i][1].hwsrc, vendor_list)}
        result.append(client_dict)

    return result


# Ping Adress
def ping_req(ip):
    ping_data = ping(ip, verbose=True)
    ping_text = str(ping_data)
    if "Request timed out" in ping_text:
        return "Request timed out"
    else:
        d = 'ms'
        ping_list = [e + d for e in ping_text.split(d) if e]
        ping_list = [e.strip('\n\r') for e in ping_list]
        ping_list = [e.strip('\r') for e in ping_list]
        ping_list = [e.strip('\n') for e in ping_list]
        return ping_list


# Port Scanner
def port_scanner(ip):
    open_ports = []
    closed_ports = []
    try:
        for port in list_of_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            else:
                closed_ports.append(port)
            s.close()
    except socket.error as error:
        print(str(error))
        sys.exit()
        open_ports = []
        closed_ports = []

    return open_ports, closed_ports


# Grabber ranek
def frame_grabber(ip, port):
    s = socket.socket()
    s.connect((ip, int(port)))
    message = s.recv(1024)
    return message


# Ip Spoofing
def ip_spoofing(ip_source, ip_destination):
    packet = scapy.IP(src=ip_source, dst=ip_destination) / scapy.ICMP()
    resp = scapy.send(packet)
    if resp:
        resp.show()
    return resp


# Flask
app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    return render('index.html', title='Network Tool', my_ip_address=my_ip_address)


@app.route('/scan/', methods=['GET', 'POST'])
def scan_interface():
    vendor_list = read_vendor_list()
    if request.method == 'POST':
        ip1 = request.form['ip1']
        ip2 = request.form['ip2']
        ip3 = request.form['ip3']
        ip4 = request.form['ip4']
        ipwide = request.form['ipwide']
        data = str(ip1 + '.' + ip2 + '.' + ip3 + '.' + ip4 + '/' + ipwide)
        searched_ip = data
        scan_interface.scanned_output = scan(searched_ip, vendor_list)
        print(data)
        return render('index.html', title='Network Tool', scaned=scan_interface.scanned_output,
                      my_ip_address=my_ip_address)
    return render('index.html', title='Network Tool', scaned=scan_interface.scanned_output, my_ip_address=my_ip_address)


@app.route('/actions/<chosen_ip>', methods=['GET', 'POST'])
def actions(chosen_ip):
    actions.chosen_ip = chosen_ip
    print(chosen_ip)
    for s in scan_interface.scanned_output:
        if s['ip'] == chosen_ip:
            actions.chosen_mac = s['mac']
            chosen_vendor = s['vendor']
            try:
                try:
                    ping_list = s['ping']
                except KeyError:
                    ping_list = "?"
                try:
                    open_ports = s['open_ports']
                    closed_ports = s['closed_ports']
                except KeyError:
                    open_ports = "?"
                    closed_ports = "?"
            except KeyError:
                pass

    return render('actions.html', title='Network Tool', chosen_ip=chosen_ip, chosen_mac=actions.chosen_mac
                  , chosen_vendor=chosen_vendor, ping=ping_list, o_ports=open_ports, c_ports=closed_ports)


@app.route('/actions/check_vendor/', methods=['GET', 'POST'])
def check_vendor_online():
    r = requests.get(api_url + actions.chosen_mac)
    print(r.content.decode())
    print(actions.chosen_mac)
    value = r.content.decode()
    for s in scan_interface.scanned_output:
        if s['mac'] == actions.chosen_mac:
            if "errors" in value:
                s['vendor'] = "Nie znaleziono w bazie danych"
            else:
                s['vendor'] = r.content.decode()
            chosen_ip = s['ip']
    return redirect(url_for('actions', chosen_ip=actions.chosen_ip))


@app.route('/actions/ping/', methods=['GET', 'POST'])
def ping_chosen_ip():
    ping_list = ping_req(actions.chosen_ip)
    for s in scan_interface.scanned_output:
        if s['ip'] == actions.chosen_ip:
            s['ping'] = ping_list
    return redirect(url_for('actions', chosen_ip=actions.chosen_ip))


@app.route('/actions/scan_ports/', methods=['GET', 'POST'])
def scan_ports():
    open_ports, closed_ports = port_scanner(actions.chosen_ip)
    for s in scan_interface.scanned_output:
        if s['ip'] == actions.chosen_ip:
            s['open_ports'] = open_ports
            s['closed_ports'] = closed_ports
    return redirect(url_for('actions', chosen_ip=actions.chosen_ip))


@app.route('/actions/ip_spoofing/', methods=['GET', 'POST'])
def view_ip_spoofing():
    try:
        ip_spoofing("192.168.50.44", "192.168.50.1")
    except:
        pass
    return redirect(url_for('actions', chosen_ip=actions.chosen_ip))


# Dodanie routow do frame_grabbera


if __name__ == '__main__':
    my_ip_address = socket.gethostbyname(socket.gethostname())
    app.run()
