from flask import Flask, render_template, request
import sqlite3, subprocess
import xml.etree.ElementTree as ET

# TODO: Make and implement design decision for hostnames vs. ip addresses
#       Fix DB locking on concurrent writes
#       database datetime() wrong
#       Implement secure coding practices.  Do we deploy this inside a container?  Nmap has to run as root for -sS
#       Enumeration for scripts for host

def nmap_scan(hosts):

    conn = sqlite3.connect('SPRAK.db')

    #fast UDP and TCP scan for open ports
    for host in hosts:
        nmap_cmd = ["nmap", "-sS", "-sU", "-T4", "-p", "-", "-oA", "static/logs/" + host, host]    
        subprocess.run(nmap_cmd)

        xmltree = ET.parse("static/logs/" + host + ".xml")
        xmlroot = xmltree.getroot()

        openports = []

        # grab open ports from nmap xml file to do second deep fingerprint scan
        for port in xmlroot.iter('port'):
            openports.append(port.attrib['portid'])

        portarg = ",".join(openports)
        
        if len(openports) > 0:
            nmap_cmd = ["nmap", "-sS", "-sU", "-A", "-p", portarg, "-oA", "static/logs/" + host, host]
            subprocess.run(nmap_cmd)

        ### parse xml and insert into database ###
        xmltree = ET.parse("static/logs/" + host + ".xml")
        xmlroot = xmltree.getroot()

        os_fingerprints = []

        for osmatch in xmlroot.iter('osmatch'):          #parse os match element and accuracy attribute
            os_fingerprints.append("[ " + osmatch.attrib['name'] + " :: Accuracy: " + osmatch.attrib['accuracy'] + " ]")

        os_fingerprint = " & ".join(os_fingerprints)

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
            product = "NULL"
            extrainfo = "NULL"
            state = "NULL"
            script_name = "NULL"
            script_output = "NULL"

            for service in port.iter(tag="service"):
                if 'name' in service.attrib.keys():
                    service_name = service.attrib['name']
                if 'version' in service.attrib.keys():
                    version = service.attrib['version']
                if 'product' in service.attrib.keys():
                    product = service.attrib['product']
                if 'extrainfo' in service.attrib.keys():
                    extrainfo = service.attrib['extrainfo']
            
            for state in port.iter(tag="state"):
                if 'state' in state.attrib.keys():
                    state = state.attrib['state']

            c = conn.execute("SELECT * FROM nmap_ports WHERE port_number=? AND protocol=? AND nmap_id=?;", (port_number, protocol, nmap_id))
            
            if c.fetchone() is None:
                conn.execute("INSERT INTO nmap_ports (nmap_id, port_number, protocol, state, service, version, product, \
                              extrainfo, has_script) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);", (nmap_id, port_number, protocol, state, service_name, version, product, extrainfo, "no script"))
            else: 
                conn.execute("UPDATE nmap_ports SET service = ?, version = ?, product = ?, extrainfo = ?, state = ? WHERE \
                              nmap_id = ? AND port_number = ? AND protocol=?;", (service_name, version, product, extrainfo, state, nmap_id, port_number, protocol))
            
            c = conn.execute("SELECT id FROM nmap_ports WHERE nmap_id = ? AND port_number = ? AND protocol = ?", (nmap_id, port_number, protocol))
            nmap_ports_id = c.fetchone()[0]

            for script in port.iter(tag="script"):
                if 'id' in script.attrib.keys():
                    script_name = script.attrib['id']
                if 'output' in script.attrib.keys():
                    script_output = script.attrib['output']
                
                c = conn.execute("SELECT id FROM nmap_scripts WHERE nmap_ports_id = ? AND name = ?;", (nmap_ports_id, script_name))

                if c.fetchone() is None:
                    conn.execute("INSERT INTO nmap_scripts (name, output, nmap_ports_id) VALUES (?, ?, ?);", (script_name, script_output, nmap_ports_id))
                    conn.execute("UPDATE nmap_ports SET has_script = 'has script' WHERE id = ?;", (nmap_ports_id,))
                else:
                    conn.execute("UPDATE nmap_scripts SET output = ? WHERE nmap_ports_id = ? AND name = ?;", (script_output, nmap_ports_id, script_name))

        conn.commit()

    conn.close()

def get_hosts():

    conn = sqlite3.connect('SPRAK.db')
    c = conn.execute("SELECT ip_address FROM hosts;")
    iplist = c.fetchall()
    conn.commit()
    conn.close()
    return iplist

def sql_query(query, args):

    conn = sqlite3.connect('SPRAK.db')
    c = conn.execute(query, args)

    results = c.fetchall()

    conn.commit()
    conn.close()

    return results

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

    dbhosts = get_hosts()

    return render_template("hostlogs.html", hostlist=dbhosts)

@app.route("/log")
def log():

    host = request.args.get("h")

    scanenum = sql_query("SELECT timestamp, os_fingerprint FROM hosts JOIN nmap ON hosts.id = nmap.host_id \
                         WHERE ip_address = ?", (host,))
    
    portenum = sql_query("SELECT port_number, protocol, state, service, version, product, \
                        extrainfo, has_script FROM hosts JOIN nmap ON hosts.id = nmap.host_id JOIN nmap_ports ON \
                        nmap.id = nmap_ports.nmap_id WHERE ip_address = ? ORDER BY port_number;", (host,))

    scriptenum = sql_query("SELECT port_number, protocol, name, output FROM hosts JOIN nmap ON hosts.id = nmap.host_id \
                            JOIN nmap_ports ON nmap.id = nmap_ports.nmap_id JOIN nmap_scripts \
                            ON nmap_ports.id = nmap_scripts.nmap_ports_id WHERE ip_address = ?; \
                            ", (host,))

    timestamp = scanenum[0][0]
    os_fingerprints = scanenum[0][1]

    return render_template("log.html", ip_address=host, lastscan=timestamp, \
                           osmatches=os_fingerprints, ports=portenum, scripts=scriptenum)
