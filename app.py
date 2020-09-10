from flask import Flask, render_template, request, jsonify
import sqlite3, subprocess
import xml.etree.ElementTree as ET

DBFILE = 'SPRAK.db'

# TODO: 
#       Fix DB locking on concurrent writes
#       database datetime() wrong
#       Implement secure coding practices.  Do we deploy this inside a container?  Nmap has to run as root for -sS

def nmap_scan(hosts):

    conn = sqlite3.connect(DBFILE)

    #fast UDP and TCP scan for open ports
    for host in hosts:
        nmap_cmd = ["nmap", "-sS", "-sU", "-T4", "-p", "-", "-oA", "static/logs/" + host, host]
        print("Nmap Scan Phase 1: ", nmap_cmd)
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
            print("Nmap Scan Phase 2: ", nmap_cmd)
            subprocess.run(nmap_cmd)

        ### parse xml and insert into database ###
        xmltree = ET.parse("static/logs/" + host + ".xml")
        xmlroot = xmltree.getroot()

        os_fingerprints = []

        #parse os match element and accuracy attribute
        for osmatch in xmlroot.iter('osmatch'):          
            os_fingerprints.append("[ " + osmatch.attrib['name'] + " :: Accuracy: " + osmatch.attrib['accuracy'] + " ]")

        os_fingerprint = " & ".join(os_fingerprints)

        #check for existing host in database
        row = sql_query_one("SELECT id FROM hosts WHERE host=?;", (host,))

        # if host doesn't exist, insert into hosts table along with nmap scan and fingerprint
        if row is None:
            conn.execute("INSERT INTO hosts (host) VALUES (?);", (host,))
            conn.commit()

            #grab new host primary key
            host_id = sql_query_one("SELECT id FROM hosts WHERE host=?;", (host,))[0]

            #insert new scan into nmap table or else update existing nmap scan in nmap table
            conn.execute("INSERT INTO nmap (host_id, os_fingerprint, timestamp) VALUES (?, ?, datetime('now'));", (host_id, os_fingerprint))
            conn.commit()
        else:
            host_id = row[0]
            conn.execute("UPDATE nmap SET os_fingerprint = ?, timestamp = datetime('now') WHERE host_id=?;", (os_fingerprint, host_id))
            conn.commit()

        #grab nmap table primary key to use on nmap_ports table
        nmap_id = sql_query_one("SELECT id FROM nmap WHERE host_id=?;", (host_id,))[0]

        # iterate over all hostscript elements in nmap xml file and add to nmap_host_scripts table or update if entry exists
        for hostscript in xmlroot.iter(tag="hostscript"):

            for script in hostscript.iter(tag="script"):

                if 'id' in script.attrib.keys():
                    host_script_name = script.attrib['id']
                else:
                    host_script_name = "NULL"

                if 'output' in script.attrib.keys():
                    host_script_output = script.attrib['output']
                else:
                    host_script_output = "NULL"

                #add to table or update table if exists
                if sql_query_one("SELECT id FROM nmap_host_scripts WHERE host_id = ? AND name = ?;", (host_id, host_script_name)) is None:
                    conn.execute("INSERT INTO nmap_host_scripts (name, output, host_id) VALUES (?, ?, ?);", (host_script_name, host_script_output, host_id))
                else:
                    conn.execute("UPDATE nmap_host_scripts SET output = ? WHERE host_id = ? AND name = ?;", (host_script_output, host_id, host_script_name))

                conn.commit()

        # iterate over all port, service, and state elements in nmap xml file and add to nmap_ports table or update if exists
        for port in xmlroot.iter(tag="port"):

            port_number = port.attrib['portid']
            protocol = port.attrib['protocol']

            service_name = "NULL"
            version = "NULL"
            product = "NULL"
            extrainfo = "NULL"
            state = "NULL"
            script_name = "NULL"
            script_output = "NULL"

            #service element iteration
            for service in port.iter(tag="service"):
                if 'name' in service.attrib.keys():
                    service_name = service.attrib['name']
                if 'version' in service.attrib.keys():
                    version = service.attrib['version']
                if 'product' in service.attrib.keys():
                    product = service.attrib['product']
                if 'extrainfo' in service.attrib.keys():
                    extrainfo = service.attrib['extrainfo']
            
            #state element iteration
            for state in port.iter(tag="state"):
                if 'state' in state.attrib.keys():
                    state = state.attrib['state']
            
            #add to table or update table if exists
            if sql_query_one("SELECT * FROM nmap_ports WHERE port_number=? AND protocol=? AND nmap_id=?;", (port_number, protocol, nmap_id)) is None:
                conn.execute("INSERT INTO nmap_ports (nmap_id, port_number, protocol, state, service, version, product, \
                              extrainfo, has_script) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);", (nmap_id, port_number, protocol, state, service_name, version, product, extrainfo, "no script"))
            else: 
                conn.execute("UPDATE nmap_ports SET service = ?, version = ?, product = ?, extrainfo = ?, state = ? WHERE \
                              nmap_id = ? AND port_number = ? AND protocol=?;", (service_name, version, product, extrainfo, state, nmap_id, port_number, protocol))
            
            conn.commit()
            nmap_ports_id = sql_query_one("SELECT id FROM nmap_ports WHERE nmap_id = ? AND port_number = ? AND protocol = ?", (nmap_id, port_number, protocol))[0]

            #iterate over script elements inside port element and add to nmap_scripts table or update if exists
            for script in port.iter(tag="script"):
                if 'id' in script.attrib.keys():
                    script_name = script.attrib['id']
                if 'output' in script.attrib.keys():
                    script_output = script.attrib['output']
                
                #add to table or update table if exists
                if sql_query_one("SELECT id FROM nmap_scripts WHERE nmap_ports_id = ? AND name = ?;", (nmap_ports_id, script_name)) is None:
                    conn.execute("INSERT INTO nmap_scripts (name, output, nmap_ports_id) VALUES (?, ?, ?);", (script_name, script_output, nmap_ports_id))
                    conn.execute("UPDATE nmap_ports SET has_script = 'has script' WHERE id = ?;", (nmap_ports_id,))
                else:
                    conn.execute("UPDATE nmap_scripts SET output = ? WHERE nmap_ports_id = ? AND name = ?;", (script_output, nmap_ports_id, script_name))

        conn.commit()

    conn.close()

def vhost_scan(hosts):

    conn = sqlite3.connect(DBFILE)

    for host in hosts:

        gobuster_cmd = ["gobuster", "vhost", "-w", "wordlists/subdomains-top1million-110000.txt", "-k", "-o", "static/logs/" + host + ".vhost", "-u", host]
        subprocess.run(gobuster_cmd)

        if ":" in host:
            host, port_number = host.split(":")
        else:
            port_number = "80"

        with open("static/logs/" + host + ".vhost", "r") as vhostFile:

            host_id = sql_query_one("SELECT id FROM hosts WHERE host=?", (host,))

            if host_id is None:

                c = conn.execute("INSERT INTO hosts (host) VALUES (?);", (host,))
                conn.commit()

                host_id = sql_query_one("SELECT id FROM hosts WHERE host=?", (host,))

            nmap_id = sql_query_one("SELECT id FROM nmap WHERE host_id=?", (host_id,))

            if nmap_id is None:

                c = conn.execute("INSERT INTO nmap (host_id) VALUES (?);", (host_id,))
                conn.commit()

                nmap_id = sql_query_one("SELECT id FROM nmap WHERE host_id=?", (host_id,))

            nmap_ports_id = sql_query_one("SELECT id FROM nmap_ports WHERE port_number=? AND protocol='tcp' AND nmap_id=?;", (port_number, nmap_id))

            if nmap_ports_id is None: 
                c = conn.execute("INSERT INTO nmap_ports (port_number, protocol, nmap_id) VALUES (?, ?, ?);", (port_number, "tcp", nmap_id))
                conn.commit()

            nmap_ports_id = sql_query_one("SELECT id FROM nmap_ports WHERE nmap_id=? AND protocol='tcp' AND nmap_id=?;", (nmap_id, protocol, nmap_id))

            for line in vhostFile.readline():
                vhostenum = line  #parse this, prob reg expression

                vhost_id = sql_query_one("SELECT id FROM vhosts WHERE vhost=?;", (vhostenum,))

                if vhost_id is None:
                    c = conn.execute("INSERT INTO vhosts (vhost, nmap_ports_id) VALUES (?, ?);", (vhostenum, nmap_ports_id))
                    conn.commit()

    
    conn.close()

def sql_query_all(query, args):

    conn = sqlite3.connect(DBFILE)
    c = conn.execute(query, args)

    results = c.fetchall()

    conn.commit()
    conn.close()

    return results

def sql_query_one(query, args):

    conn = sqlite3.connect(DBFILE)
    c = conn.execute(query, args)

    result = c.fetchone()

    conn.commit()
    conn.close()

    return result


app = Flask(__name__)

@app.route("/")
def index():

    return render_template("index.html")

@app.route("/<scantype>/<hostlist>")
def portscan(scantype, hostlist):

    hosts = hostlist.split(",")
    print(f"Received Hosts: {hosts}")

    if scantype == "portscan":
        nmap_scan(hosts)
        return "port scan complete."
    elif scantype == "vhostscan":
        vhost_scan(hosts)
        return "vhost scan complete."
    elif scantype == "dirscan":
        dir_scan(hosts)
        return "dir scan complete."
    else:
        return "Not Found"

@app.route("/hostlogs")
def hostlogs():

    conn = sqlite3.connect(DBFILE)
    c = conn.execute("SELECT host FROM hosts;")

    dbhosts = c.fetchall()

    conn.commit()
    conn.close()

    return render_template("hostlogs.html", hostlist=dbhosts)

@app.route("/log/<host>/ports")
def ports_log(host):

    scanenum = sql_query_all("SELECT timestamp, os_fingerprint FROM hosts JOIN nmap ON hosts.id = nmap.host_id \
                         WHERE host = ?", (host,))
    
    hostscriptenum = sql_query_all("SELECT name, output FROM nmap_host_scripts JOIN hosts ON host_id=hosts.id WHERE host = ?;",(host,))

    portenum = sql_query_all("SELECT port_number, protocol, state, service, version, product, \
                        extrainfo, has_script FROM hosts JOIN nmap ON hosts.id = nmap.host_id JOIN nmap_ports ON \
                        nmap.id = nmap_ports.nmap_id WHERE host = ? ORDER BY port_number;", (host,))

    scriptenum = sql_query_all("SELECT port_number, protocol, name, output FROM hosts JOIN nmap ON hosts.id = nmap.host_id \
                            JOIN nmap_ports ON nmap.id = nmap_ports.nmap_id JOIN nmap_scripts \
                            ON nmap_ports.id = nmap_scripts.nmap_ports_id WHERE host = ?; \
                            ", (host,))

    timestamp = scanenum[0][0]
    os_fingerprints = scanenum[0][1]

    if request.content_type == "application/json" and request.accept_mimetypes.accept_json:
        json_log = [{ "Host": host, "Last Scan": timestamp, "OS Fingerprints": os_fingerprints}]

        for hostscript in hostscriptenum:
            json_log.append({"Script Name" : hostscript[0], "Output" : hostscript[1]})

        for port in portenum:
            json_log.append({"Port" : port[0], "Protocol" : port[1], "State" : port[2], "Service" : port[3], "Version" : port[4], "Product" : port[5], \
                            "Info" : port[6]})
            
            for script in scriptenum:
                if script[0] == port[0] and script[1] == port[1]:
                    json_log[len(json_log) -1].update({script[2] : script[3]})
            
        return jsonify(json_log)
    else:
        return render_template("log.html", host=host, lastscan=timestamp, \
                                osmatches=os_fingerprints, ports=portenum, scripts=scriptenum, hostscripts=hostscriptenum)

@app.route("/log/<host>/vhost")
def vhost_log(host):

    return "Not implemented"

@app.route("/log/<host>/dir")
def dir_log(host):

    return "Not implemented"