from flask import Flask, render_template, request, jsonify
import sqlite3, subprocess, re
import xml.etree.ElementTree as ET
import glob, os, socket

DBPATH = "projects/"
DIR_WORDLISTS = ["wordlists/raft-large-directories.txt", "wordlists/raft-large-files.txt", "wordlists/raft-large-words.txt"]

# TODO: 
#       Fix DB locking on concurrent writes
#       database datetime() wrong
#       Implement secure coding practices.  Do we deploy this inside a container?  Nmap has to run as root for -sS

def log_dir(dbfile):

    projectname = re.search("(.*).db", dbfile)

    try:  
        os.mkdir("static/logs/" + projectname.group(1))  
    except OSError as error:  
        print(error)

    return projectname.group(1) + "/"

def valid_ip(address):
    try: 
        socket.inet_aton(address)
        return True
    except:
        return False

def query_service_type(host, port_number, dbfile):

    row = sql_query_one("SELECT service FROM nmap_ports JOIN nmap ON nmap_ports.nmap_id=nmap.id JOIN hosts \
                         ON nmap.host_id=hosts.id WHERE (service='http' OR service='https') \
                         AND port_number=? AND host=?;",(port_number, host), dbfile)
    
    if row is None:
        return "NULL"
    else:
        return row[0]

def nmap_scan(hosts, dbfile):

    conn = sqlite3.connect(DBPATH + dbfile)
    
    #fast UDP and TCP scan for open ports
    for host in hosts:
        
        nmap_cmd = ["nmap", "-sS", "-T4", "-p", "-", "-oA", "static/logs/" + log_dir(dbfile) + host, host]
        print("Nmap Scan Phase 1: ", nmap_cmd)
        subprocess.run(nmap_cmd)

        xmltree = ET.parse("static/logs/" + log_dir(dbfile) + host + ".xml")
        xmlroot = xmltree.getroot()

        openports = []

        # grab open ports from nmap xml file to do second deep fingerprint scan
        for port in xmlroot.iter('port'):
            openports.append(port.attrib['portid'])

        portarg = ",".join(openports)
        
        if len(openports) > 0:
            nmap_cmd = ["nmap", "-sS", "-A", "-p", portarg, "-oA", "static/logs/" + log_dir(dbfile) + host, host]
            print("Nmap Scan Phase 2: ", nmap_cmd)
            subprocess.run(nmap_cmd)

        ### parse xml and insert into database ###
        xmltree = ET.parse("static/logs/" + log_dir(dbfile) + host + ".xml")
        xmlroot = xmltree.getroot()

        os_fingerprints = []

        # parse os match element and accuracy attribute
        for osmatch in xmlroot.iter('osmatch'):          
            os_fingerprints.append("[ " + osmatch.attrib['name'] + " :: Accuracy: " + osmatch.attrib['accuracy'] + " ]")

        os_fingerprint = " & ".join(os_fingerprints)

        # check for existing host in database
        row = sql_query_one("SELECT id FROM hosts WHERE host=?;", (host,), dbfile)

        # if host doesn't exist, insert into hosts table along with nmap scan and fingerprint
        if row is None:
            conn.execute("INSERT INTO hosts (host) VALUES (?);", (host,))
            conn.commit()

            # grab new host primary key
            host_id = sql_query_one("SELECT id FROM hosts WHERE host=?;", (host,), dbfile)[0]

            # insert new scan into nmap table or else update existing nmap scan in nmap table
            conn.execute("INSERT INTO nmap (host_id, os_fingerprint, timestamp) VALUES (?, ?, datetime('now'));", (host_id, os_fingerprint))
            conn.commit()
        else:
            host_id = row[0]
            conn.execute("UPDATE nmap SET os_fingerprint = ?, timestamp = datetime('now') WHERE host_id=?;", (os_fingerprint, host_id))
            conn.commit()

        # grab nmap table primary key to use on nmap_ports table
        nmap_id = sql_query_one("SELECT id FROM nmap WHERE host_id=?;", (host_id,), dbfile)[0]

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
                if sql_query_one("SELECT id FROM nmap_host_scripts WHERE host_id = ? AND name = ?;", (host_id, host_script_name), dbfile) is None:
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
            if sql_query_one("SELECT * FROM nmap_ports WHERE port_number=? AND protocol=? AND nmap_id=?;", (port_number, protocol, nmap_id), dbfile) is None:
                conn.execute("INSERT INTO nmap_ports (nmap_id, port_number, protocol, state, service, version, product, \
                              extrainfo, has_script) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);", (nmap_id, port_number, protocol, state, service_name, version, product, extrainfo, "no script"))
            else: 
                conn.execute("UPDATE nmap_ports SET service = ?, version = ?, product = ?, extrainfo = ?, state = ? WHERE \
                              nmap_id = ? AND port_number = ? AND protocol=?;", (service_name, version, product, extrainfo, state, nmap_id, port_number, protocol))
            
            conn.commit()
            nmap_ports_id = sql_query_one("SELECT id FROM nmap_ports WHERE nmap_id = ? AND port_number = ? AND protocol = ?", (nmap_id, port_number, protocol), dbfile)[0]

            #iterate over script elements inside port element and add to nmap_scripts table or update if exists
            for script in port.iter(tag="script"):
                if 'id' in script.attrib.keys():
                    script_name = script.attrib['id']
                if 'output' in script.attrib.keys():
                    script_output = script.attrib['output']
                
                #add to table or update table if exists
                if sql_query_one("SELECT id FROM nmap_scripts WHERE nmap_ports_id = ? AND name = ?;", (nmap_ports_id, script_name), dbfile) is None:
                    conn.execute("INSERT INTO nmap_scripts (name, output, nmap_ports_id) VALUES (?, ?, ?);", (script_name, script_output, nmap_ports_id))
                    conn.execute("UPDATE nmap_ports SET has_script = 'has script' WHERE id = ?;", (nmap_ports_id,))
                else:
                    conn.execute("UPDATE nmap_scripts SET output = ? WHERE nmap_ports_id = ? AND name = ?;", (script_output, nmap_ports_id, script_name))

        conn.commit()
    
    conn.close()

def vhost_scan(hosts, dbfile):

    conn = sqlite3.connect(DBPATH + dbfile)

    for host in hosts:

        if ":" in host:
            host, port_number = host.split(":")
        else:
            port_number = "80"

        service = query_service_type(host, port_number, dbfile)

        if valid_ip(host) == False:
            gobuster_cmd = ["gobuster", "vhost", "-w", "wordlists/subdomains-top1million-110000.txt", "-k", "-o", "static/logs/" \
                            + log_dir(dbfile) + host + ":" + port_number + ".vhost", "-u", service + "://" + host]
        else:
            gobuster_cmd = ["gobuster", "vhost", "-w", "wordlists/dummylist.txt", "-k", "-o", "static/logs/" \
                            + log_dir(dbfile) + host + ":" + port_number + ".vhost", "-u", service + "://" + host]

        subprocess.run(gobuster_cmd)

        with open("static/logs/" + log_dir(dbfile) + host + ":" + port_number + ".vhost", "r") as vhostFile:

            row = sql_query_one("SELECT id FROM hosts WHERE host=?;", (host,), dbfile)
            
            if row is None:
                c = conn.execute("INSERT INTO hosts (host) VALUES (?);", (host,))
                conn.commit()

                host_id = sql_query_one("SELECT id FROM hosts WHERE host=?;", (host,), dbfile)[0]
            else:
                host_id = row[0]

            row = sql_query_one("SELECT id FROM nmap WHERE host_id=?;", (host_id,), dbfile)
            
            if row is None:
                c = conn.execute("INSERT INTO nmap (host_id) VALUES (?);", (host_id,))
                conn.commit()

                nmap_id = sql_query_one("SELECT id FROM nmap WHERE host_id=?;", (host_id,), dbfile)[0]
            else:
                nmap_id = row[0]

            row = sql_query_one("SELECT id FROM nmap_ports WHERE port_number=? AND protocol='tcp' AND nmap_id=?;", (port_number, nmap_id), dbfile)

            if row is None: 
                c = conn.execute("INSERT INTO nmap_ports (port_number, protocol, nmap_id) VALUES (?, ?, ?);", (port_number, "tcp", nmap_id))
                conn.commit()
           
                nmap_ports_id = sql_query_one("SELECT id FROM nmap_ports WHERE nmap_id=? AND protocol='tcp' AND nmap_id=?;", (nmap_id, nmap_id), dbfile)[0]  
            else:
                nmap_ports_id = row[0]
            
            row = sql_query_one("SELECT id FROM vhosts WHERE vhost=? AND nmap_ports_id=?;", (host, nmap_ports_id), dbfile)

            if row is None:
                c = conn.execute("INSERT INTO vhosts (vhost, status, nmap_ports_id) VALUES (?, ?, ?);", (host, "200", nmap_ports_id))
                conn.commit()
                
            for line in vhostFile:
                vhost = re.search("(.*): (.*) \(Status: (.*)\).*", line)

                row = sql_query_one("SELECT id FROM vhosts WHERE vhost=? AND nmap_ports_id=?;", (vhost.group(2), nmap_ports_id), dbfile)

                if row is None:
                    c = conn.execute("INSERT INTO vhosts (vhost, status, nmap_ports_id) VALUES (?, ?, ?);", (vhost.group(2), vhost.group(3), nmap_ports_id))
                else:
                    c = conn.execute("UPDATE vhosts SET status=? WHERE id=?;", (vhost.group(3), row[0]))
                    
                conn.commit()

    conn.close()

def dir_scan(hosts, dbfile):

    conn = sqlite3.connect(DBPATH + dbfile)

    for host in hosts:

        #pull host and port number from url if formatted like so - google.com:5000 else default to port 80
        if ":" in host:
            host, port_number = host.split(":")
        else:
            port_number = "80"

        service = query_service_type(host, port_number, dbfile)

        # temp fix: if host wasn't scanned no port entry will exist so we are scanning if service returns NULL
        if service == "NULL":
            nmap_scan(host, dbfile)
            service = query_service_type(host, port_number, dbfile)

            #if service still returns null, return
            if service == "NULL":
                print("Invalid protocol for dir scan.  Must be http/https.")
                return

        for wordlist in DIR_WORDLISTS:
            gobuster_cmd = ["gobuster", "dir", "-w", wordlist, "-o", "static/logs/" + log_dir(dbfile) + host + ":" + port_number + ".dir", "-k",  "-u", service + "://" + host + ":" + port_number]
            #dirb_cmd = ["dirb", service + "://" + host + ":" + port_number, wordlist, "-o", "static/logs/" + log_dir(dbfile) + host + ":" + port_number + ".dir"]
            #dirb_cmd = ["dirb", service + "://" + host + ":" + port_number, "-o", "static/logs/" + log_dir(dbfile) + host + ":" + port_number + ".dir"]

            subprocess.run(gobuster_cmd)

            with open("static/logs/" + log_dir(dbfile) + host + ":" + port_number + ".dir", "r") as dirFile:

                #query to check if this host is already a vhost so we don't create duplicates in both vhosts and hosts table
                row = sql_query_one("SELECT id FROM vhosts WHERE vhost=?;", (host,), dbfile)

                #if vhost exists, grab the id from host table, else query to see if the host is in the hosts table
                if row is not None:
                    row = sql_query_one("SELECT hosts.id FROM hosts JOIN nmap ON hosts.id=nmap.host_id JOIN nmap_ports ON nmap.id=nmap_id JOIN vhosts \
                                        ON nmap_ports.id=nmap_ports_id WHERE vhost=? AND port_number=?;", (host, port_number), dbfile)
                else:
                    row = sql_query_one("SELECT id FROM hosts WHERE host=?;", (host,), dbfile)
                
                #create new entry in hosts table if host doesn't exist, else grab the id of the host
                if row is None:
                    c = conn.execute("INSERT INTO hosts (host) VALUES (?);", (host,))
                    conn.commit()

                    host_id = sql_query_one("SELECT id FROM hosts WHERE host=?;", (host,), dbfile)[0]
                else:
                    host_id = row[0]

                #try to grab id of port scan in nmap table for host
                row = sql_query_one("SELECT id FROM nmap WHERE host_id=?;", (host_id,), dbfile)
                
                #create nmap scan entry if one doesn't exist for host, else use existing nmap table id of scan
                if row is None:
                    c = conn.execute("INSERT INTO nmap (host_id) VALUES (?);", (host_id,))
                    conn.commit()

                    nmap_id = sql_query_one("SELECT id FROM nmap WHERE host_id=?;", (host_id,), dbfile)[0]
                else:
                    nmap_id = row[0]

                #try to grab id of port number from nmap_ports table for associated host/scan, will use this id as foreign key in vhosts table
                row = sql_query_one("SELECT id FROM nmap_ports WHERE port_number=? AND protocol='tcp' AND nmap_id=?;", (port_number, nmap_id), dbfile)

                #if port entry doesn't exist, manually create new one to link to vhost
                if row is None: 
                    c = conn.execute("INSERT INTO nmap_ports (port_number, protocol, nmap_id) VALUES (?, ?, ?);", (port_number, "tcp", nmap_id))
                    conn.commit()
            
                    nmap_ports_id = sql_query_one("SELECT id FROM nmap_ports WHERE nmap_id=? AND protocol='tcp' AND nmap_id=?;", (nmap_id, nmap_id), dbfile)[0]  
                else:
                    nmap_ports_id = row[0]

                #try to grab id from vhosts
                row = sql_query_one("SELECT id FROM vhosts WHERE vhost=? AND nmap_ports_id=?;", (host, nmap_ports_id), dbfile)

                #if vhost doesn't exist, create entry else grab id from table
                if row is None:
                    c = conn.execute("INSERT INTO vhosts (vhost, status, nmap_ports_id) VALUES (?, ?, ?);", (host, "200", nmap_ports_id))
                    conn.commit()

                    vhost_id = sql_query_one("SELECT id FROM vhosts WHERE vhost=? AND nmap_ports_id=?;", (host, nmap_ports_id), dbfile)[0]
                else:
                    vhost_id = row[0]

                #open results file from dir scan and create new entries in dir table if they don't exist
                for line in dirFile:

                    # regex for gobuster
                    path = re.search("(.*) \(Status: (.*)\)", line)
                    
                    # regex for dirb
                    #path = re.search("==> DIRECTORY: (.*)", line)
                    #filematch = re.search("\+ (.*) \(CODE:(.*)\|SIZE:(.*)\)", line)

                    if path is not None:

                        fullpath = service + "://" + host + path.group(1)

                        row = sql_query_one("SELECT id FROM dir WHERE path=? AND vhost_id=?;", (fullpath, vhost_id), dbfile)

                        if row is None:
                            c = conn.execute("INSERT INTO dir (path, status, vhost_id) VALUES (?, ?, ?);", (fullpath, path.group(2), vhost_id))
                        else:
                            c = conn.execute("UPDATE dir SET status=? WHERE id=?;", (path.group(2), row[0]))
                    
                        conn.commit()
                    
                    # alternate match for dirb
                    #if filematch is not None:

                    #    row = sql_query_one("SELECT id FROM dir WHERE path=? AND vhost_id=?;", (filematch.group(1), vhost_id), dbfile)

                    #    if row is None:
                    #        c = conn.execute("INSERT INTO dir (path, status, vhost_id) VALUES (?, ?, ?);", (filematch.group(1), filematch.group(2), vhost_id))
                    #    else:
                    #        c = conn.execute("UPDATE dir SET status=? WHERE id=?;", (filematch.group(2), row[0]))
                    
                    #    conn.commit()

    conn.close()

def sql_query_all(query, args, dbfile):

    conn = sqlite3.connect(DBPATH + dbfile)
    c = conn.execute(query, args)

    results = c.fetchall()

    conn.commit()
    conn.close()

    return results

def sql_query_one(query, args, dbfile):

    conn = sqlite3.connect(DBPATH + dbfile)
    c = conn.execute(query, args)

    result = c.fetchone()

    conn.commit()
    conn.close()

    return result


app = Flask(__name__)

@app.route("/")
def index():

    projects = []

    for filename in glob.glob('projects/*.db'):
        projectname = re.search("projects/(.*).db", filename)
        projects.append(projectname.group(1))

    return render_template("index.html", projects=projects)

@app.route("/<scantype>/<project>/<hostlist>")
def portscan(scantype, project, hostlist):

    dbfile = project.upper() + ".db"
    conn = sqlite3.connect(DBPATH + dbfile)
    conn.execute("CREATE TABLE IF NOT EXISTS nmap (id INTEGER PRIMARY KEY, os_fingerprint TEXT, timestamp TEXT, \
                  host_id INTEGER NOT NULL, FOREIGN KEY (host_id) REFERENCES hosts(id));")
    conn.execute("CREATE TABLE IF NOT EXISTS nmap_scripts (id INTEGER PRIMARY KEY, name TEXT, output TEXT, nmap_ports_id \
                  INTEGER NOT NULL, FOREIGN KEY (nmap_ports_id) REFERENCES nmap_ports(id));")
    conn.execute("CREATE TABLE IF NOT EXISTS nmap_host_scripts (id INTEGER PRIMARY KEY, name TEXT, output TEXT, host_id \
                  INTEGER NOT NULL, FOREIGN KEY (host_id) REFERENCES hosts(id));")
    conn.execute("CREATE TABLE IF NOT EXISTS hosts (id INTEGER PRIMARY KEY, host TEXT);")
    conn.execute("CREATE TABLE IF NOT EXISTS vhosts (id INTEGER PRIMARY KEY, vhost TEXT, \
                  status TEXT, nmap_ports_id INTEGER NOT NULL, FOREIGN KEY (nmap_ports_id) REFERENCES nmap_ports(id));")
    conn.execute("CREATE TABLE IF NOT EXISTS dir (id INTEGER PRIMARY KEY, path TEXT, status TEXT, vhost_id INTEGER NOT NULL, \
                  FOREIGN KEY (vhost_id) REFERENCES vhosts(id));")
    conn.execute("CREATE TABLE IF NOT EXISTS nmap_ports (id INTEGER PRIMARY KEY, port_number TEXT, protocol TEXT, state TEXT, \
                  service TEXT, version TEXT, product TEXT, extrainfo TEXT, has_script TEXT, nmap_id INTEGER NOT NULL, \
                  FOREIGN KEY (nmap_id) REFERENCES nmap(id));")
    conn.commit()
    conn.close()

    hosts = hostlist.split(",")
    print(f"Received Hosts: {hosts}")

    if scantype == "portscan":
        nmap_scan(hosts, dbfile)
        return "port scan complete."
    elif scantype == "vhostscan":
        vhost_scan(hosts, dbfile)
        return "vhost scan complete."
    elif scantype == "dirscan":
        dir_scan(hosts, dbfile)
        return "dir scan complete."
    elif scantype == "autoscan":
        nmap_scan(hosts, dbfile)
        http_hosts = []
        vhosts = []

        for host in hosts:
            rows = sql_query_all("SELECT nmap_ports.id, port_number, nmap_id FROM nmap_ports \
                                             JOIN nmap ON nmap_ports.nmap_id=nmap.id JOIN hosts ON nmap.host_id=hosts.id \
                                             WHERE (service='http' OR service='https') AND host=?;",(host,), dbfile)
            
            for row in rows:
                http_hosts.append(host + ":" + row[1])

        if http_hosts != []:
            vhost_scan(http_hosts, dbfile)

            for host in hosts:
                rows = sql_query_all("SELECT vhost, port_number, status FROM vhosts JOIN nmap_ports ON vhosts.nmap_ports_id=nmap_ports.id \
                                     JOIN nmap ON nmap_ports.nmap_id=nmap.id JOIN hosts ON nmap.host_id=hosts.id \
                                     WHERE host=? ", (host,), dbfile)
                
                for row in rows:
                    if row[2] != "400" and row[2] != "404":
                        vhosts.append(row[0] + ":" + row[1])

            if vhosts != []:
                dir_scan(vhosts, dbfile)

        return "auto scan complete"
    else:
        return "Not Found"

@app.route("/hostlogs/<project>")
def hostlogs(project):

    dbfile = project.upper() + ".db"

    conn = sqlite3.connect(DBPATH + dbfile)
    c = conn.execute("SELECT host FROM hosts;")

    dbhosts = c.fetchall()

    conn.commit()
    conn.close()

    return render_template("hostlogs.html", hostlist=dbhosts, project=project)

@app.route("/log/<project>/<host>/ports")
def ports_log(project, host):

    dbfile = project.upper() + ".db"

    scanenum = sql_query_all("SELECT timestamp, os_fingerprint FROM hosts JOIN nmap ON hosts.id = nmap.host_id \
                              WHERE host = ?", (host,), dbfile)
    
    hostscriptenum = sql_query_all("SELECT name, output FROM nmap_host_scripts JOIN hosts ON host_id=hosts.id WHERE host = ?;",(host,), dbfile)

    portenum = sql_query_all("SELECT port_number, protocol, state, service, version, product, \
                              extrainfo, has_script FROM hosts JOIN nmap ON hosts.id = nmap.host_id JOIN nmap_ports ON \
                              nmap.id = nmap_ports.nmap_id WHERE host = ? ORDER BY port_number;", (host,), dbfile)

    scriptenum = sql_query_all("SELECT port_number, protocol, name, output FROM hosts JOIN nmap ON hosts.id = nmap.host_id \
                                JOIN nmap_ports ON nmap.id = nmap_ports.nmap_id JOIN nmap_scripts \
                                ON nmap_ports.id = nmap_scripts.nmap_ports_id WHERE host = ?;", (host,), dbfile)
            
    vhostscans = sql_query_all("SELECT port_number FROM vhosts JOIN nmap_ports ON vhosts.nmap_ports_id=nmap_ports.id WHERE vhost=?;", (host,), dbfile)

    if scanenum == []:
        return "Does not exist!"

    if vhostscans == []:
        vhostscans = "NULL"

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
                                osmatches=os_fingerprints, ports=portenum, scripts=scriptenum, \
                                hostscripts=hostscriptenum, vhostscans=vhostscans, project=project)

@app.route("/log/<project>/<host>/vhosts")
def vhost_log(project, host):

    dbfile = project.upper() + ".db"

    if ":" in host:
        host, port_number = host.split(":")
    else:
        port_number = "80"

    vhostenum = sql_query_all("SELECT vhost, status FROM vhosts JOIN nmap_ports ON vhosts.nmap_ports_id=nmap_ports.id \
                               JOIN nmap ON nmap_ports.nmap_id=nmap.id JOIN hosts ON hosts.id=nmap.host_id \
                               WHERE port_number=? AND host=?;", (port_number, host), dbfile)

    direnum = sql_query_all("SELECT dir.id, vhost FROM dir JOIN vhosts ON dir.vhost_id=vhosts.id JOIN \
                                 nmap_ports ON vhosts.nmap_ports_id=nmap_ports.id \
                                 JOIN nmap ON nmap_ports.nmap_id=nmap.id JOIN hosts ON hosts.id=nmap.host_id \
                                 WHERE port_number=? AND host=?;", (port_number, host), dbfile)

    if request.content_type == "application/json" and request.accept_mimetypes.accept_json:
        json_log = []

        for vhost in vhostenum:
            json_log.append({vhost[0] : vhost[1]})
            
        return jsonify(json_log)
    else:
        return render_template("vhosts.html", vhosts=vhostenum, direnum=direnum, port=port_number, host=host, project=project)

@app.route("/log/<project>/<host>/dir")
def dir_log(project, host):

    dbfile = project.upper() + ".db"

    if ":" in host:
        host, port_number = host.split(":")
    else:
        port_number = "80"

    direnum = sql_query_all("SELECT path, dir.status, host FROM dir JOIN vhosts ON dir.vhost_id=vhosts.id JOIN \
                               nmap_ports ON vhosts.nmap_ports_id=nmap_ports.id \
                               JOIN nmap ON nmap_ports.nmap_id=nmap.id JOIN hosts ON hosts.id=nmap.host_id \
                               WHERE port_number=? AND vhost=? ORDER BY dir.status;", (port_number, host), dbfile)

    if direnum == []:
        return "Does not exist!"
    elif request.content_type == "application/json" and request.accept_mimetypes.accept_json:
        json_log = []

        for path in direnum:
            json_log.append({path[0] : path[1]})
            
        return jsonify(json_log)
    else:
        return render_template("dir.html", vhost=host, direnum=direnum, port=port_number, project=project)