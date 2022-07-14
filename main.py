from flask import Flask, request
from flask import render_template as render
from flask import *
from flask_table import Table, Col
import scapy.all as scapy
import tkinter as tk
import tkinter.ttk as ttk
import socket
import requests
import argparse
from pythonping import ping

url = "https://api.macvendors.com/"


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
    # print(s_mac)
    s_mac = s_mac[0] + s_mac[1] + s_mac[2] + s_mac[3] + s_mac[4] + s_mac[5]
    # print(s_mac)
    for v in vendor_list:
        if v[0].casefold() == s_mac.casefold():
            vendor = v[1].strip()
            break
    return vendor


# skanowanie
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
                ping_list = s['ping']
            except:
                ping_list = "NULL"
                pass

    return render('actions.html', title='Network Tool', chosen_ip=chosen_ip, chosen_mac=actions.chosen_mac
                  , chosen_vendor=chosen_vendor, ping=ping_list)


@app.route('/actions/check_vendor/', methods=['GET', 'POST'])
def check_vendor_online():
    if request.method == 'POST':
        r = requests.get(url + actions.chosen_mac)
        print(r.content.decode())
        print(actions.chosen_mac)
        vale = r.content.decode()
        for s in scan_interface.scanned_output:
            if s['mac'] == actions.chosen_mac:
                if "errors" in vale:
                    s['vendor'] = "Nie znaleziono w bazie danych"
                else:
                    s['vendor'] = r.content.decode()
                chosen_ip = s['ip']
        return redirect(url_for('actions', chosen_ip=chosen_ip))


@app.route('/actions/ping/', methods=['GET', 'POST'])
def ping_chosen_ip():
    ping_list = ping(actions.chosen_ip, verbose=True)
    for s in scan_interface.scanned_output:
        if s['ip'] == actions.chosen_ip:
            s['ping'] = ping_list
    return redirect(url_for('actions', chosen_ip=actions.chosen_ip))


if __name__ == '__main__':
    my_ip_address = socket.gethostbyname(socket.gethostname())
    app.run()
