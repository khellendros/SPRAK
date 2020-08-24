from flask import Flask, render_template, request
import sqlite3, subprocess
import xml.etree.ElementTree as ET

conn = sqlite3.connect('SPRAK.db')

def nmap_scan(hosts):
    #fast UDP and TCP scan for open ports
    for host in hosts:
        nmap_cmd = ["nmap", "-sT", "-T4", "-p", "-", "-oA", "logs/" + host, host]    
        subprocess.run(nmap_cmd)

        xmltree = ET.parse("logs/" + host + ".xml")
        xmlroot = xmltree.getroot()

        openports = []
        #grab open ports from nmap xml file to do second deep fingerprint scan
        for port in xmlroot.iter('port'):
            openports.append(port.attrib['portid'])

        portarg = ",".join(openports)
        nmap_cmd = ["nmap", "-sT", "-sU", "-A", "-p", portarg, "-oA", "logs/" + host, host]
        subprocess.run(nmap_cmd)


app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan")
def scan():
    hostsarg = request.args.get("hosts")
    hosts = hostsarg.split(",")
    print(f"Received Hosts: {hosts}")

    nmap_scan(hosts)

    return "Scan Complete!"