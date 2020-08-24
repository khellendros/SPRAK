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

        osfingerprints = []

        for osmatch in xmlroot.iter('osmatch'):          #parse os match element and accuracy attribute
            osfingerprints.append(osmatch.attrib['name'] + " Accuracy: " + osmatch.attrib['accuracy'])

        osfingerprint = "\n".join(osfingerprints)

        c = conn.execute("SELECT * FROM hosts WHERE ip_address=?;", (host,))  #check for existing host in database

        # if host doesn't exist, insert into database along with nmap scan and fingerprint
        if c.fetchone() is None:
            conn.execute("INSERT INTO hosts (ip_address) VALUES (?);", (host,))
            c = conn.execute("SELECT id FROM hosts WHERE ip_address=?;", (host,))   #grab new host primary key
        
            host_id = c.fetchone()[0]

            conn.execute("INSERT INTO nmap (host_id, osfingerprint) VALUES (?, ?);", (host_id, osfingerprint))
        else:
            host_id = c.fetchone()[0]
            conn.execute("UPDATE nmap SET osfingerprint = ? WHERE host_id=?;", (osfingerprint, host_id))

        c = conn.execute("SELECT id FROM nmap WHERE host_id=?;", (host_id,))  #grab nmap table primary key to use on nmap_ports table
        nmap_id = c.fetchone()[0]

        # iterate over all port and service elements in nmap xml file and add ports if they don't exist for 
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

            c = conn.execute("SELECT * FROM nmap_ports WHERE port_number=? AND protocol=?;", (port_number, protocol))
            
            if c.fetchone() is None:
                conn.execute("INSERT INTO nmap_ports (nmap_id, port_number, protocol, service, service_fingerprint) VALUES (?, ?, ?, ?, ?);", 
                            (nmap_id, port_number, protocol, service_name, version))
            else: 
                conn.execute("UPDATE nmap_ports SET service = ?, service_fingerprint = ? WHERE nmap_id=? AND port=? AND protocol=?;", 
                            (service_name, version, port_number, protocol))

        conn.commit()

    conn.close()



app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/nmapscan")
def scan():
    hostsarg = request.args.get("hosts")
    hosts = hostsarg.split(",")
    print(f"Received Hosts: {hosts}")

    nmap_scan(hosts)

    return "Scan Complete!"