import func, colorama, time
from cryptography.fernet import Fernet

colorama.init()

func.generall.clear()
print(colorama.Fore.GREEN)
print(func.generall.display_header(" UHT "))

while True:
    try:
        print(colorama.Fore.GREEN)
        print("\n", func.os.getcwd())
        CMD:str = func.generall.ask("-> ", colorama.Fore.GREEN)

        if CMD == "help":
            print(f"{colorama.Fore.BLUE}commands:")
            print(f"""
exit                            (to exit the program)
port-scan                       (for scanning ports of an IP address)
socket                          (for socket communication)
    - socket::enc               (for encrypted communication between 2 UHT's)
    - socket::file              (to transfer a file safely to another UHT user)
        - socket::file::recv    (to recv a file)
        - socket::file::send    (to send a file)
encrypt / enc                   (to encrypt a file)
decrypt / dec                   (to decrypt a file, which was encrypted before)
net                             (for locking / unlocking    usage: net [username] --lock or net [username] --unlock)
passwd                          (to change password     usage: passwd [username] [new password])
{colorama.Fore.GREEN}""")
        
        elif CMD == "exit":
            func.generall.clear()
            print("You chose exit...")
            break

        elif CMD == "port-scan":
            IP = func.generall.ask("IP: ", colorama.Fore.GREEN)
            PORTS = {
                20: "FTP-Datenübertragung",
                21: "FTP-Steuerverbindung",
                22: "SSH – sichere Remote-Verbindung",
                23: "Telnet – unverschlüsselte Remote-Shell",
                25: "SMTP – E-Mail-Versand",
                53: "DNS – Namensauflösung",
                67: "DHCP-Server",
                68: "DHCP-Client",
                80: "HTTP – Webserver (unverschlüsselt)",
                110: "POP3 – E-Mail-Abruf",
                143: "IMAP – E-Mail-Abruf",
                443: "HTTPS – Webserver (verschlüsselt)",
                3306: "MySQL-Datenbank",
                5432: "PostgreSQL-Datenbank",
                6379: "Redis – In-Memory-Datenbank",
                8080: "Alternativer HTTP-Port / Web-Proxy"
            }

            PORT_GESCHW:str = func.generall.ask("Fast / Normal / Slow: ", colorama.Fore.GREEN)
            PORT_GESCHW = PORT_GESCHW.lower()

            print("[*] PORT selection")
            if PORT_GESCHW == "fast":
                pass
            elif PORT_GESCHW == "normal":
                for i in range(1, 1025):
                    if i not in PORTS:
                        PORTS[i] = ""
            elif PORT_GESCHW == "slow":
                for i in range(1, 65537):
                    if i not in PORTS:
                        PORTS[i] = ""
            
            print("[*] now scanning")
            time.sleep(0.5)

            aktive = []
            for port in PORTS:
                sock:func.socket.socket = func.net.create_TCP()
                sock.settimeout(0.2)
                res = sock.connect_ex((IP, port))
                sock.close()

                if res == 0:
                    aktive.append(port)
                    print("[*] open port: ", port)
            
            print("[*] now conclusion: port list, with description to some known ports")
            for port in aktive:
                print(f"     {port} - {PORTS[port]}")

        elif CMD.startswith("socket"):
            if CMD == "socket::enc":
                Client_Server:str = func.generall.ask("Client or Server? ", colorama.Fore.GREEN)

                if Client_Server.lower() == "client":
                    client:func.socket.socket = func.net.create_TCP()
                    IP:str = func.generall.ask("IP: ", colorama.Fore.GREEN)
                    PORT:str = func.generall.ask("PORT: ", colorama.Fore.GREEN)
                    client.connect((IP, int(PORT)))

                    p_len = int.from_bytes(func.net.recv_exact(client, 8), "big")
                    p = func.net.recv_exact(client, p_len)
                    g_len = int.from_bytes(func.net.recv_exact(client, 8), "big")
                    g = func.net.recv_exact(client, g_len)
                    DH_KEY = func.net.DH(int(p), int(g))

                    their_pub_key_len = int.from_bytes(func.net.recv_exact(client, 8), "big")
                    their_pub_key = func.net.recv_exact(client, their_pub_key_len)

                    pub_bytes = DH_KEY.public_key.to_bytes((DH_KEY.public_key.bit_length() +7) // 8, byteorder="big")
                    client.sendall(len(pub_bytes).to_bytes(8, "big") + pub_bytes)

                    DH_KEY.generate_other(int.from_bytes(their_pub_key, "big"))

                    while True:
                        txt:str = func.generall.ask("\nYour Message (or exit): ", colorama.Fore.BLUE)
                        txt = DH_KEY.encrypt(txt.encode())
                        client.sendall(len(txt).to_bytes(8, "big") + txt)

                        if DH_KEY.decrypt(txt) == b"exit":
                            client.close()
                            break

                        ans_len = int.from_bytes(func.net.recv_exact(client, 8), "big")
                        ans = func.net.recv_exact(client, ans_len)
                        ans = DH_KEY.decrypt(ans).decode()
                        print("\n", colorama.Fore.RED, ans)

                        if ans == "exit":
                            client.close()
                            break
                    print(colorama.Fore.GREEN)

                elif Client_Server.lower() == "server":
                    server:func.socket.socket = func.net.create_TCP()
                    PORT:str = func.generall.ask("PORT: ", colorama.Fore.GREEN)
                    server.bind(("0.0.0.0", int(PORT)))
                    server.listen(1)

                    conn, addr = server.accept()
                    print(f"{colorama.Fore.BLUE}[*] connection from {addr}")
                    p = str(0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1).encode()
                    g = str(2).encode()
                    conn.sendall(len(p).to_bytes(8, "big") + p)
                    conn.sendall(len(g).to_bytes(8, "big") + g)

                    DH_KEY = func.net.DH(int(p), int(g))

                    pub_bytes = DH_KEY.public_key.to_bytes((DH_KEY.public_key.bit_length() +7) // 8, byteorder="big")

                    conn.sendall(len(pub_bytes).to_bytes(8, "big") + pub_bytes)
                    their_pub_key_len = int.from_bytes(func.net.recv_exact(conn, 8), "big")
                    their_pub_key = func.net.recv_exact(conn, their_pub_key_len)

                    DH_KEY.generate_other(int.from_bytes(their_pub_key, "big"))

                    while True:
                        ans_len = int.from_bytes(func.net.recv_exact(conn, 8), "big")
                        ans = func.net.recv_exact(conn, ans_len)
                        ans = DH_KEY.decrypt(ans).decode()
                        print("\n", colorama.Fore.RED, ans)

                        if ans == "exit":
                            conn.close()
                            break

                        txt:str = func.generall.ask("\nYour Text (or exit): ", colorama.Fore.BLUE)
                        txt = DH_KEY.encrypt(txt.encode())
                        conn.sendall(len(txt).to_bytes(8, "big") + txt)

                        if DH_KEY.decrypt(txt) == b"exit":
                            conn.close()
                            break
                    print(colorama.Fore.GREEN)

                else:
                    print("This wasn't an Option!")
                    continue

            elif CMD.startswith("socket::file"):
                if CMD == "socket::file::send":
                    FILEPATH = func.generall.ask("Filepath: ", colorama.Fore.GREEN)
                    
                    p:int = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
                    g:int = 2

                    DH_KEY = func.net.DH(p, g)
                    
                    server:func.socket.socket = func.net.create_TCP()
                    server.bind(("0.0.0.0", 13321))
                    server.listen(1)

                    conn, addr = server.accept()
                    print("[*] conection from ", addr)

                    conn.sendall(p.to_bytes((p.bit_length()+7)//8, "big"))
                    conn.sendall(g.to_bytes((g.bit_length()+7)//8, "big"))

                    pub_bytes = DH_KEY.public_key.to_bytes((DH_KEY.public_key.bit_length()+7)//8, byteorder="big")
                    conn.sendall(len(pub_bytes).to_bytes(8, "big") + pub_bytes)

                    their_pub_key_len = int.from_bytes(func.net.recv_exact(conn, 8), "big")
                    their_pub_key = func.net.recv_exact(conn, their_pub_key_len)

                    DH_KEY.generate_other(int.from_bytes(their_pub_key, "big"))

                    Filename = DH_KEY.encrypt(func.generall.ask("The Name of the File: ", colorama.Fore.GREEN).encode())
                    conn.send(len(Filename).to_bytes(6, "big") + Filename)

                    with open(FILEPATH, "rb") as data:
                        while True:
                            chunk = data.read(64 * 1024)
                            if not chunk:
                                break

                            enc = DH_KEY.encrypt(chunk)
                            conn.sendall(len(enc).to_bytes(4, "big") + enc)
                    conn.close()

                elif CMD == "socket::file::recv":
                    IP:str = func.generall.ask("IP: ", colorama.Fore.GREEN)
                    client:func.socket.socket = func.net.create_TCP()
                    client.connect((IP, 13321))

                    p = int.from_bytes(client.recv(8192))
                    g = int.from_bytes(client.recv(4096))

                    DH_KEY = func.net.DH(p, g)

                    their_pub_key_len = int.from_bytes(func.net.recv_exact(client, 8), "big")
                    their_pub_key = func.net.recv_exact(client, their_pub_key_len)

                    pub_bytes = DH_KEY.public_key.to_bytes((DH_KEY.public_key.bit_length()+7)//8, "big")
                    client.sendall(len(pub_bytes).to_bytes(8, "big") + pub_bytes)

                    DH_KEY.generate_other(int.from_bytes(their_pub_key, "big"))

                    Filename_len = int.from_bytes(func.net.recv_exact(client, 6), "big")
                    Filename = DH_KEY.decrypt(func.net.recv_exact(client, Filename_len))

                    with open(Filename.decode(), "wb") as data:
                        while True:
                            try:
                                chunk_len = int.from_bytes(func.net.recv_exact(client, 4), "big")
                                chunk = func.net.recv_exact(client, chunk_len)

                                dec = DH_KEY.decrypt(chunk)
                                data.write(dec)
                            except ConnectionError:
                                client.close()
                                break

                else:
                    print("This wasn't an Option!")
                    continue

            else:
                print("This wasn't an Option!")
                continue

        elif CMD in ["encrypt", "enc"]:
            FILEPATH = func.generall.ask("Filepath: ", colorama.Fore.GREEN)
            KEY_FILE = func.generall.ask("KEY filename (Nothing = standard): ", colorama.Fore.GREEN) or FILEPATH+".key"

            if not func.os.path.exists(FILEPATH):
                print(colorama.Fore.RED, "This Path doesn't exist! (Filepath: )", colorama.Fore.GREEN)
                continue

            KEY = Fernet.generate_key()
            fernet = Fernet(KEY)

            with open(KEY_FILE, "wb") as key_file:
                key_file.write(KEY)

            with open(FILEPATH, "rb") as original_file:
                enc = fernet.encrypt( original_file.read() )
            
            with open(FILEPATH+".encrypted", "wb") as enc_file:
                enc_file.write(enc)

            func.os.remove(FILEPATH)
            print("[*] Done!")
        
        elif CMD in ["decrypt", "dec"]:
            FILEPATH:str = func.generall.ask("Filepath: ", colorama.Fore.GREEN)
            KEY_FILE:str = func.generall.ask("KEY filename: ", colorama.Fore.GREEN)

            if not func.os.path.exists(FILEPATH) or not func.os.path.exists(KEY_FILE):
                print(colorama.Fore.RED, "This Path doesn't exist! (I dont know which of them)", colorama.Fore.GREEN)
                continue
            
            KEY = open(KEY_FILE, "rb").read()
            fernet = Fernet(KEY)

            with open(FILEPATH, "rb") as enc_file:
                content = fernet.decrypt( enc_file.read() )
            
            with open(FILEPATH.replace(".encrypted", ""), "wb") as original_file:
                original_file.write(content)
            
            func.os.remove(FILEPATH)
            func.os.remove(KEY_FILE)
            print("[*] Done!")

        elif CMD.startswith("net "):
            CMD_PART = CMD.split(" ")
            
            if CMD_PART[-1] == "--lock":
                if func.os.name == "nt":
                    func.os.system(f"net user {CMD_PART[1]} /ACTIVE:no")
                else:
                    func.os.system(f"sudo usermod -L {CMD_PART[1]}")

            elif CMD_PART[-1] == "--unlock":
                if func.os.name == "nt":
                    func.os.system(f"net user {CMD_PART[1]} /ACTIVE:yes")
                else:
                    func.os.system(f"sudo usermod -U {CMD_PART[1]}")
            else:
                print("This wasn't an Option!")
        
        elif CMD.startswith("passwd "):
            CMD_PART = CMD.split(" ")

            if func.os.name == "nt":
                func.os.system(f"net user {CMD_PART[1]} {CMD_PART[2]}")
            else:
                func.os.system(CMD)

        else:
            print("This wasn't an Option!")

    except KeyboardInterrupt:
        func.generall.clear()
        print("KeyboardInterrupt")
        break