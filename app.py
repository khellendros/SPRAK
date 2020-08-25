from flask import Flask, render_template, request
import sqlite3, subprocess
import xml.etree.ElementTree as ET

def nmap_scan(hosts):
    conn = sqlite3.connect('SPRAK.db')
    #fast UDP and TCP scan for open ports
    for host in hosts:
        nmap_cmd = ["nmap", "-sS", "-sU", "-T4", "-p", "-", "-oA", "logs/" + host, host]    
        subprocess.run(nmap_cmd)

        xmltree = ET.parse("logs/" + host + ".xml")
        xmlroot = xmltree.getroot()

        openports = []

        # grab open ports from nmap xml file to do second deep fingerprint scan
        for port in xmlroot.iter('port'):
            openports.append(port.attrib['portid'])

        portarg = ",".join(openports)
        nmap_cmd = ["nmap", "-sS", "-sU", "-A", "-p", portarg, "-oA", "logs/" + host, host]
        subprocess.run(nmap_cmd)

        ### parse xml and insert into database ###
        xmltree = ET.parse("logs/" + host + ".xml")
        xmlroot = xmltree.getroot()

        os_fingerprints = []

        for osmatch in xmlroot.iter('osmatch'):          #parse os match element and accuracy attribute
            os_fingerprints.append(osmatch.attrib['name'] + " Accuracy: " + osmatch.attrib['accuracy'])

        os_fingerprint = "\n".join(os_fingerprints)

        c = conn.execute("SELECT id FROM hosts WHERE ip_address=?;", (host,))  #check for existing host in database
        row = c.fetchone()

        # if host doesn't exist, insert into hosts table along with nmap scan and fingerprint
        if row is None:
            conn.execute("INSERT INTO hosts (ip_address) VALUES (?);", (host,))
            c = conn.execute("SELECT id FROM hosts WHERE ip_address=?;", (host,))   #grab new host primary key
        
            host_id = c.fetchone()[0]

            #insert new scan into nmap table or else update existing nmap scan in nmap table
            conn.execute("INSERT INTO nmap (host_id, os_fingerprint, timestamp) VALUES (?, ?, datetime('now'));", (host_id, os_fingerprint))
        else:
            host_id = row[0]
            conn.execute("UPDATE nmap SET os_fingerprint = ?, timestamp = datetime('now') WHERE host_id=?;", (os_fingerprint, host_id))

        c = conn.execute("SELECT id FROM nmap WHERE host_id=?;", (host_id,))  #grab nmap table primary key to use on nmap_ports table
        nmap_id = c.fetchone()[0]

        # iterate over all port and service elements in nmap xml file and add ports to nmap_ports table if they don't exist for 
        # new scan and update existing service fingerprints

        for port in xmlroot.iter('port'):
            port_number = port.attrib['portid']
            protocol = port.attrib['protocol']

            service_name = "NULL"
            version = "NULL"

            for service in port.iter(tag="service"):
                if 'name' in service.attrib.keys():
                    service_name = service.attrib['name']
                if 'version' in service.attrib.keys():
                    version = service.attrib['version']
                if 'product' in service.attrib.keys():
                    product = service.attrib['product']
                if 'extrainfo' in service.attrib.keys():
                    extrainfo = service.attrib['extrainfo']

            c = conn.execute("SELECT * FROM nmap_ports WHERE port_number=? AND protocol=?;", (port_number, protocol))
            
            if c.fetchone() is None:
                conn.execute("INSERT INTO nmap_ports (nmap_id, port_number, protocol, service, service_fingerprint, product, extrainfo) VALUES (?, ?, ?, ?, ?, ?, ?);", 
                            (nmap_id, port_number, protocol, service_name, version, product, extrainfo))
            else: 
                conn.execute("UPDATE nmap_ports SET service = ?, service_fingerprint = ?, product = ?, extrainfo = ? WHERE nmap_id=? AND port_number=? AND protocol=?;", 
                            (service_name, version, product, extrainfo, nmap_id, port_number, protocol))

        conn.commit()

    conn.close()

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/nmapscan")
def nmapscan():
    hostsarg = request.args.get("hosts")
    hosts = hostsarg.split(",")
    print(f"Received Hosts: {hosts}")

    nmap_scan(hosts)

    return "Scan Complete!"

@app.route("/hostlogs")
def hostlogs():
    return render_template("hostlogs.html")