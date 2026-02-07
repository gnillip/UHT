import os, socket, secrets, hashlib, json, colorama
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scapy.layers.l2 import ARP, Ether, srp

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
        def __init__(self, target_ip:str, gateway_ip:str):
            self.target_ip = target_ip
            self.gateway_ip = gateway_ip
        
        def get_mac(ip:str) -> str:
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
    
if __name__ == "__main__":
    generall.clear()
    print(generall.display_header("test in func.py"))
    mac = net.MITM.get_mac("192.168.178.57")
    print(mac)