import socket
import sys

import requests
import scapy.all as scapy
from flask import *
from flask import render_template as render
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


# Szukanie w liście producenta
def search_vendor(mac, vendor_list):
    value = mac.split(":")
    s_mac = ""
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

    if len(open_ports) < 1:
        open_ports = "[?]"

    return open_ports, closed_ports


# Grabber ramek
def frame_grabber(ip, port):
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((ip, int(port)))
        message = s.recv(1024)
    except TimeoutError:
        message = "Time out"
    return message


# Ip Spoofing

#def ip_spoofing(ip_source, ip_destination):
#    packet = scapy.IP(src=ip_source, dst=ip_destination) / scapy.ICMP()
#    resp = scapy.send(packet)
#    packet_list = []
#    if resp:
#        for r in resp:
#            print(r.show())
#            packet_list.append(r.show(dump=True))
#        resp.show()
#    print(packet_list)
#    return resp


# snifffing packets
def ip_sniff(ip_source, times):
    pack_sniff = scapy.sniff(prn=lambda x: x.summary(), count=int(times), filter="host " + str(ip_source))
    packets_more_information = []
    for p in pack_sniff:
        packets_more_information.append(p.mysummary())
    return pack_sniff, packets_more_information


def check_if_scanned():
    check = False
    try:
        if view_scan_interface.scanned_output is not None:
            check = True
    except AttributeError:
        pass
    return check


# Flask
app = Flask(__name__)


# Index + skanowanie sieci
@app.route('/', methods=['GET', 'POST'])
def index():
    return render('index.html', title='Network Tool', my_ip_address=my_ip_address)


# lista po skanowaniu
@app.route('/scan/', methods=['GET', 'POST'])
def view_scan_interface():
    vendor_list = read_vendor_list()
    if request.method == 'POST':
        ip1 = request.form['ip1']
        ip2 = request.form['ip2']
        ip3 = request.form['ip3']
        ip4 = request.form['ip4']
        ipwide = request.form['ipwide']
        data = str(ip1 + '.' + ip2 + '.' + ip3 + '.' + ip4 + '/' + ipwide)
        searched_ip = data
        view_scan_interface.scanned_output = scan(searched_ip, vendor_list)
        # print(data)
        return render('index.html', title='Network Tool', scaned=view_scan_interface.scanned_output,
                      my_ip_address=my_ip_address)
    return render('index.html', title='Network Tool', scaned=view_scan_interface.scanned_output,
                  my_ip_address=my_ip_address)


# Akcje na wybrany IP
@app.route('/actions/<chosen_ip>', methods=['GET', 'POST'])
def view_actions(chosen_ip):
    view_actions.chosen_ip = chosen_ip
    print(chosen_ip)
    for s in view_scan_interface.scanned_output:
        if s['ip'] == chosen_ip:
            view_actions.chosen_mac = s['mac']
            chosen_vendor = s['vendor']
            try:
                try:
                    ping_list = s['ping']
                except KeyError:
                    ping_list = "?"
                try:
                    open_ports = s['open_ports']
                    #print(open_ports)
                    closed_ports = s['closed_ports']
                except KeyError:
                    open_ports = "?"
                    closed_ports = "?"
                try:
                    sniff_list = s['sniff']
                    sniff_summary = s['sniff_summary']
                except KeyError:
                    sniff_list = "?"
                    sniff_summary = "?"
                try:
                    frame_list = s['frame']
                except KeyError:
                    frame_list = "?"
            except KeyError:
                pass

    return render('actions.html', title='Network Tool', chosen_ip=chosen_ip, chosen_mac=view_actions.chosen_mac,
                  chosen_vendor=chosen_vendor, ping=ping_list, o_ports=open_ports, c_ports=closed_ports,
                  sniff=sniff_list, sniff_summary=sniff_summary, frame=frame_list)


# Sprawdzenie ip online
@app.route('/actions/check_vendor/', methods=['GET', 'POST'])
def view_check_vendor_online():
    r = requests.get(api_url + view_actions.chosen_mac)
    value = r.content.decode()
    for s in view_scan_interface.scanned_output:
        if s['mac'] == view_actions.chosen_mac:
            if "errors" in value:
                s['vendor'] = "Nie znaleziono w bazie danych"
            else:
                s['vendor'] = r.content.decode()
    return redirect(url_for('view_actions', chosen_ip=view_actions.chosen_ip))


@app.route('/actions/ping/', methods=['GET', 'POST'])
def view_ping_chosen_ip():
    ping_list = ping_req(view_actions.chosen_ip)
    for s in view_scan_interface.scanned_output:
        if s['ip'] == view_actions.chosen_ip:
            s['ping'] = ping_list
    return redirect(url_for('view_actions', chosen_ip=view_actions.chosen_ip))


@app.route('/actions/scan_ports/', methods=['GET', 'POST'])
def view_scan_ports():
    open_ports, closed_ports = port_scanner(view_actions.chosen_ip)
    for s in view_scan_interface.scanned_output:
        if s['ip'] == view_actions.chosen_ip:
            s['open_ports'] = open_ports
            s['closed_ports'] = closed_ports
    return redirect(url_for('view_actions', chosen_ip=view_actions.chosen_ip))


@app.route('/actions/ip_sniffing/', methods=['GET', 'POST'])
def view_ip_sniffing():
    if request.method == 'POST':
        times = request.form['value_of_times']
        try:
            sniff, sniff_more_information = ip_sniff(view_actions.chosen_ip, times)
            for s in view_scan_interface.scanned_output:
                if s['ip'] == view_actions.chosen_ip:
                    s['sniff'] = sniff
                    s['sniff_summary'] = sniff_more_information
        except KeyError:
            pass
    return redirect(url_for('view_actions', chosen_ip=view_actions.chosen_ip))


# Dodanie frame_grabbera
@app.route('/actions/frame_grab/', methods=['GET', 'POST'])
def view_frame_grab():
    if request.method == 'POST':
        chosen_port = request.form['chosen_port']
        try:
            gotten_message = frame_grabber(view_actions.chosen_ip, chosen_port)
            for s in view_scan_interface.scanned_output:
                if s['ip'] == view_actions.chosen_ip:
                    # print('On port ' + str(chosen_port) + ' : ' + str(gotten_message))
                    s['frame'] = 'On port ' + str(chosen_port) + ' : ' + str(gotten_message)
        except ConnectionRefusedError:
            pass
        return redirect(url_for('view_actions', chosen_ip=view_actions.chosen_ip))


# Konfiguracja Portów
@app.route('/port_config/', methods=['GET', 'POST'])
def view_port_config():
    check = check_if_scanned()
    return render('port_config.html', title='Network Tool', list_of_ports=list_of_ports, my_ip_address=my_ip_address,
                  scan_interface=check)


# Dodawanie portow
@app.route('/add_port/', methods=['GET', 'POST'])
def add_port():
    if request.method == 'POST':
        new_port = request.form['new_port']
        list_of_ports.append(int(new_port))
    return redirect(url_for('view_port_config'))


# Usuwanie portow
@app.route('/del_port/', methods=['GET', 'POST'])
def del_port():
    if request.method == 'POST':
        port_to_del = request.form['port_to_del']
        list_of_ports.remove(int(port_to_del))
    return redirect(url_for('view_port_config'))


# Sprawdzeie Adresu Mac online
@app.route('/check_online_sep/', methods=['GET', 'POST'])
def view_check_online_sep():
    check = check_if_scanned()
    value = None
    return render('check_online_sep.html', title='Network Tool', scan_interface=check, value=value)


# Sprawdzeie Adresu Mac online akcja
@app.route('/check_online_sep_act/', methods=['GET', 'POST'])
def view_check_online_sep_act():
    check = check_if_scanned()
    if request.method == 'POST':
        mac_adrr = request.form['mac_adrr']
        r = requests.get(api_url + str(mac_adrr))
        value = r.content.decode()
    return render('check_online_sep.html', title='Network Tool', scan_interface=check, value=value)


# Osobny ping punktow
@app.route('/ping_sep/', methods=['GET', 'POST'])
def view_ping_sep():
    check = check_if_scanned()
    value = None
    return render('ping_sep.html', title='Network Tool', scan_interface=check, value=value)


# Osobny ping punktow akcja
@app.route('/ping_sep_act/', methods=['GET', 'POST'])
def view_ping_sep_act():
    check = check_if_scanned()
    if request.method == 'POST':
        ip_adrr = request.form['ip_adrr']
        value = ping_req(ip_adrr)
    return render('ping_sep.html', title='Network Tool', scan_interface=check, value=value)


# Osobne skanowanie portow
@app.route('/port_scan_sep/', methods=['GET', 'POST'])
def view_port_scan_sep():
    check = check_if_scanned()
    value1 = None
    value2 = None
    return render('port_scan_sep.html', title='Network Tool', scan_interface=check, value1=value1, value2=value2)


# Osobne skanowanie portow akcja
@app.route('/port_scan_sep_act/', methods=['GET', 'POST'])
def view_port_scan_sep_act():
    check = check_if_scanned()
    if request.method == 'POST':
        ip_adrr = request.form['ip_adrr']
        value1, value2 = port_scanner(ip_adrr)
    return render('port_scan_sep.html', title='Network Tool', scan_interface=check, value1=value1, value2=value2)


# Osobny ip sniff
@app.route('/ip_sniff_sep/', methods=['GET', 'POST'])
def view_ip_sniff_sep():
    check = check_if_scanned()
    value1 = None
    value2 = None
    return render('ip_sniff_sep.html', title='Network Tool', scan_interface=check, value1=value1, value2=value2)


# Osobny ip sniff akcja
@app.route('/ip_sniff_sep_act/', methods=['GET', 'POST'])
def view_ip_sniff_sep_act():
    check = check_if_scanned()
    if request.method == 'POST':
        ip_adrr = request.form['ip_adrr']
        times = request.form['times']
        value1, value2 = ip_sniff(ip_adrr, times)
    return render('ip_sniff_sep.html', title='Network Tool', scan_interface=check, value1=value1, value2=value2)


if __name__ == '__main__':
    my_ip_address = socket.gethostbyname(socket.gethostname())
    app.run()
