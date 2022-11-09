from ciscoaxl import axl
from tkinter import *
from zeep import Client
from zeep.cache import SqliteCache
from zeep.transports import Transport
from zeep.plugins import HistoryPlugin
from requests import Session
from requests.auth import HTTPBasicAuth
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from tkinter import messagebox
import threading
from time import sleep
import ipaddress
import logging
import requests
logging.basicConfig(
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    level=logging.INFO
)

class App(Tk):
    def __init__(self):
        self.accounts = None
        self.children_dict = dict()
        super(App, self).__init__()
        self.group = LabelFrame(self, text="Application", padx=5, pady=5)
        self.group.grid(row=0, column=0, padx=5, pady=5, columnspan=2, rowspan=2)
        # Main App
        self.entry_log = Text(self.group, height=10, width=52, bg="#a3a3a3")
        self.entry_log.grid(row=0, column=0, rowspan=5)
        # button and Entry account
        self.username = Label(self.group, text="username")
        self.username.grid(row=0, column=1, sticky=N)
        self.entry_user = Entry(self.group, width=10)
        self.entry_user.grid(row=0, column=2, sticky=W+N)

        self.password = Label(self.group, text="password")
        self.password.grid(row=1, column=1, sticky=N+W)
        self.entry_passw = Entry(self.group, width=10, show="*")
        self.entry_passw.grid(row=1, column=2, sticky=N+W)

        self.btn_start = Button(self.group, text="Erase", command=self.start_Thread)
        self.btn_start.grid(row=2, column=2)

    def Settings(self):
        settingsWindow = Toplevel()
        settingsWindow.title("Account")
        Label(settingsWindow, text="username").grid(row=0)
        Label(settingsWindow, text="password").grid(row=1)
        user = StringVar()
        Entry(settingsWindow, width=10, textvariable=user).grid(row=0, column=1)
        passw = StringVar()
        Entry(settingsWindow, width=10, show="*", textvariable=passw).grid(row=1, column=1)
        Button(settingsWindow, text="Submit", command=settingsWindow.destroy).grid(row=3, columnspan=2)
        settingsWindow.wait_window()

        return user.get(), passw.get()

    def start_Thread(self):
        threading.Thread(target=self.main_app).start()

    def Erase_Device(self, info):
        ipaddr = info["ip"]
        model = info["model"]
        if self.Check_Model_Exist(model):
            steps = self.Get_Steps(model)
            step = " ".join(i for i in steps)
            self.insert_log(f"model {model} found step {str(step)}\nStarting Erase model {model}")

            username = self.accounts[0]
            password = self.accounts[1]
            for i in steps:
                self.Insert_Key(ipaddr, username, password, i)
        else:
            self.insert_log(f"model {model} not found steps")

    @staticmethod
    def Get_Steps(model):
        data_file = open("data.conf").read().split("\n")
        for i in data_file:
            if model == i.split(",")[0]:
                return i.split(",")[1:]
        else:
            return f"Not step for model {model}"

    @staticmethod
    def Check_Model_Exist(model):
        model_ok = []
        data_file = open("data.conf").read().split("\n")
        for i in data_file:
            md = i.split(",")[0]
            model_ok.append(md)
        if model in model_ok:
            return True
        else:
            return False

    def main_app(self):
        self.insert_log("Searching for device")
        sep_id = self.Get_Sep_ID()
        for i in sep_id:
            self.insert_log(f"found {str(i)}")
            sleep(0.5)
        sleep(1)
        self.insert_log("search model & IP from SEP ID")

        all_devices = []
        for i in sep_id:
            info = self.Get_IP_from_SEP(i)
            ip = info[0]
            model = str(info[1])
            ip_n_model = {"ip": ip, "model": model}
            all_devices.append(ip_n_model)
            self.insert_log(f"{i} --> IP: {ip} model: {model}")
            sleep(0.5)
        self.insert_log("Find steps to erase IP Phone")
        self.accounts = self.Settings()
        for i in all_devices:
            self.Erase_Device(i)

    def insert_log(self, text):
        self.entry_log.insert(END, f"{text}\n")
        self.entry_log.see("end")

    def Get_Sep_ID(self):
        cucm = '10.168.30.11'
        self.username = self.entry_user.get()
        self.password = self.entry_passw.get()
        version = '12.5'
        ucm = axl(username=self.username, password=self.password, cucm=cucm, cucm_version=version)
        SEP = []
        try:
            for i in ucm.get_phones():
                if i["name"].__contains__("SEP"):
                    SEP.append(i["name"])
                else:
                    pass
            return SEP
        except:
            messagebox.showerror("error", "username or password failed")

    def Get_IP_from_SEP(self, sep):
        disable_warnings(InsecureRequestWarning)
        wsdl = 'https://ucm.sbdlab.net:8443/realtimeservice2/services/RISService70?wsdl'
        location = 'https://ucm.sbdlab.net:8443/realtimeservice2/services/RISService70'
        binding = '{http://schemas.cisco.com/ast/soap}RisBinding'

        session = Session()
        session.verify = False
        session.auth = HTTPBasicAuth(self.username, self.password)

        transport = Transport(cache=SqliteCache(), session=session, timeout=20)
        history = HistoryPlugin()
        client = Client(wsdl=wsdl, transport=transport, plugins=[history])
        service = client.create_service(binding, location)

        CmSelectionCriteria = {
            'MaxReturnedDevices': '10',
            'DeviceClass': 'Phone',
            'Status': 'Any',
            'NodeName': '',
            'SelectBy': 'Name',
            'SelectItems': {
                'item': [
                    f'{sep}'
                ]
            },
            'Protocol': 'Any',
            'DownloadStatus': 'Any'
        }

        StateInfo = ''

        try:
            resp = service.selectCmDeviceExt(CmSelectionCriteria=CmSelectionCriteria, StateInfo=StateInfo)

            IP_Addr = resp["SelectCmDeviceResult"]["CmNodes"]["item"][1]["CmDevices"]["item"][0]["IPAddress"]["item"][0]["IP"]
            Model = resp["SelectCmDeviceResult"]["CmNodes"]["item"][1]["CmDevices"]["item"][0]["Model"]

        except:
            return "None"
        return IP_Addr, Model

    def Insert_Key(self, ip, username, password, key):
        def keypad(num):
            return "XML=%3CCiscoIPPhoneExecute%3E%3CExecuteItem%20URL%3D%22Key%3AKeyPad" + num + "%22%2F%3E%3C%2FCiscoIPPhoneExecute%3E"

        def softkey(num):
            return "XML=%3CCiscoIPPhoneExecute%3E%3CExecuteItem%20URL%3D%22Key%3ASoft" + num + "%22%2F%3E%3C%2FCiscoIPPhoneExecute%3E"

        def star():
            return "XML=%3CCiscoIPPhoneExecute%3E%3CExecuteItem%20URL%3D%22Key%3AKeyPadStar%22%2F%3E%3C%2FCiscoIPPhoneExecute%3E"

        def pound():
            return "XML=%3CCiscoIPPhoneExecute%3E%3CExecuteItem%20URL%3D%22Key%3AKeyPadPound%22%2F%3E%3C%2FCiscoIPPhoneExecute%3E"

        def settings():
            return "XML=%3CCiscoIPPhoneExecute%3E%3CExecuteItem%20URL%3D%22Key%3ASettings%22%2F%3E%3C%2FCiscoIPPhoneExecute%3E"

        def applications():
            return "XML=%3CCiscoIPPhoneExecute%3E%3CExecuteItem%20URL%3D%22Key%3AApplications%22%2F%3E%3C%2FCiscoIPPhoneExecute%3E"

        def enter():
            return "XML=%3CCiscoIPPhoneExecute%3E%3CExecuteItem%20URL%3D%22Key%3ANavSelect%22%2F%3E%3C%2FCiscoIPPhoneExecute%3E"

        def up():
            return "XML=%3CCiscoIPPhoneExecute%3E%3CExecuteItem%20URL%3D%22Key%3ANavUp%22%2F%3E%3C%2FCiscoIPPhoneExecute%3E"

        def down():
            return "XML=%3CCiscoIPPhoneExecute%3E%3CExecuteItem%20URL%3D%22Key%3ANavDwn%22%2F%3E%3C%2FCiscoIPPhoneExecute%3E"

        def left():
            return "XML=%3CCiscoIPPhoneExecute%3E%3CExecuteItem%20URL%3D%22Key%3ANavLeft%22%2F%3E%3C%2FCiscoIPPhoneExecute%3E"

        def right():
            return "XML=%3CCiscoIPPhoneExecute%3E%3CExecuteItem%20URL%3D%22Key%3ANavRight%22%2F%3E%3C%2FCiscoIPPhoneExecute%3E"

        def parse(response):
            if response == '<CiscoIPPhoneError Number="1" />':
                logging.info('Error parsing CiscoIPPhoneExecute object')
            elif response == '<CiscoIPPhoneError Number="2" />':
                logging.info('Error framing CiscoIPPhoneResponse object')
            elif response == '<CiscoIPPhoneError Number="3" />':
                logging.info('Internal file error')
            elif response == '<CiscoIPPhoneError Number="4" />':
                logging.info('Authentication Error')
            elif 'Success' in response:
                logging.info('OK')
            else:
                logging.info(response)

        def remoteCTI(phone, payload):
            url = "http://" + phone + "/CGI/Execute"
            headers = {'Content-Type': "application/x-www-form-urlencoded"}
            try:
                response = requests.request("POST", url, auth=HTTPBasicAuth(username, password), data=payload,
                                            headers=headers)
                parse(response.text)
            except requests.exceptions.RequestException as e:
                logging.info(e)
            sleep(1)

        def promptForIP():
            try:
                phone = ip
                if ipaddress.ip_address(phone):
                    return phone
            except ValueError as e:
                logging.info(e)
                promptForIP()

        phone = promptForIP()

        if key.isdigit():
            if len(key) == 1:
                remoteCTI(phone, keypad(key))
            else:
                for i in range(1, int(key)):
                    remoteCTI(phone, down())

        elif key == '*':
            remoteCTI(phone, star())

        elif key == '#':
            remoteCTI(phone, pound())

        elif len(key) == 2 and key[:1] == 's' and key[1:].isdigit():
            remoteCTI(phone, softkey(key[1:]))

        elif key.lower() == 's' or key.lower() == "settings":
            remoteCTI(phone, settings())

        elif key.lower() == 'a' or key.lower() == 'applications':
            remoteCTI(phone, applications())

        elif key.lower() == 'e' or key.lower() == 'enter':
            remoteCTI(phone, enter())

        elif key.lower() == 'l' or key.lower() == 'left':
            remoteCTI(phone, left())

        elif key.lower() == 'r' or key.lower() == 'right':
            remoteCTI(phone, right())

        elif key.lower() == 'u' or key.lower() == 'up':
            remoteCTI(phone, up())

        elif key.lower() == 'd' or key.lower() == 'down':
            remoteCTI(phone, down())

        elif key == 'exit':
            exit()

        elif key == 'help':
            print('============================================')
            print('Type the key you wish to press, one at a time')
            print('0-9, # and * will press the respective digit')
            print('for Softkeys, prepend with s.. ie: s1 for Softkey 1')
            print('for Settings, type s - Applications, type a')
            print('============================================\n')

        else:
            print('Unknown command: {}'.format(key))

if __name__ == '__main__':
    app = App()
    app.title("SaoBacDau Erase IP Phone")
    app.mainloop()
