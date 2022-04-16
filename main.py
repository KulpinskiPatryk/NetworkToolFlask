from flask import Flask
from flask import render_template as render
from flask_table import Table, Col
import scapy.all as scapy


def readVendorList():
    vendorList = []
    with open("mac-vendor.txt", encoding='cp850') as my_file:
        for line in my_file:
            vendorList.append(line.split(maxsplit=1))
    return vendorList


def searchVendor(mac, vendorList):
    value = mac.split(":")
    Smac = ""
    i = 0
    vendor = ""
    for v in value:
        Smac = Smac + v
    # print(Smac)
    Smac = Smac[0] + Smac[1] + Smac[2] + Smac[3] + Smac[4] + Smac[5]
    # print(Smac)
    for v in vendorList:
        if v[0].casefold() == Smac.casefold():
            vendor = v[1].strip()
            break
    return vendor


def scan(ip, vendorList):
    arp_req_frame = scapy.ARP(pdst=ip)

    broadcast_ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

    answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout=1, verbose=False)[0]
    result = []
    for i in range(0, len(answered_list)):
        client_dict = {"ip": answered_list[i][1].psrc, "mac": answered_list[i][1].hwsrc,
                       "vendor": searchVendor(answered_list[i][1].hwsrc, vendorList)}
        result.append(client_dict)

    return result


class tableIP(Table):
    ip = Col('IP Address')
    mac = Col('MAC Address')
    vendor = Col('Vendor of Device')


# Flask
app = Flask(__name__)


@app.route('/')
def index():
    scaned = scanned_output
    return render('index.html', title='Network Tool', scaned=scaned)


if __name__ == '__main__':
    searchedIp = "192.168.50.1/24"
    vendorList = readVendorList()
    scanned_output = scan(searchedIp, vendorList)
    app.run()
