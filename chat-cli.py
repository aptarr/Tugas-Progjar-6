import socket
import json
import base64
import json
import os

IP_SERVER = "172.16.16.101"
PORT_SERVER = 8889
# IP_SERVER = "172.16.16.102"
# PORT_SERVER = 8000

class ChatClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = ("172.16.16.101",8889)
        self.sock.connect(self.server_address)
        self.tokenid=""
        
    def proses(self,cmdline):
        j=cmdline.split(" ")
        try:
            command=j[0].strip()
            if (command=='auth'):
                username=j[1].strip()
                password=j[2].strip()
                return self.login(username,password)
            if (command=='register'):
                username=j[1].strip()
                password=j[2].strip()
                nama=j[3].strip()
                negara=j[4].strip()
                return self.register(username, password, nama, negara)
            elif (command=='send'):
                usernameto = j[1].strip()
                message=""
                for w in j[2:]:
                    message="{} {}" . format(message,w)
                return self.send_message(usernameto,message)
            elif (command=='addgroup'):
                namegroup = j[1].strip()
                usergroups = ' '.join(j[2:])
                print(usergroups)
                return self.add_group(namegroup,usergroups)
            elif (command=='sendgroup'):
                usernamesto = j[1].strip()
                message=""
                for w in j[2:]:
                    message="{} {}" . format(message,w)
                return self.send_group_message(usernamesto,message)
            elif (command=='inboxgroup'):
                namegroup = j[1].strip()
                return self.inbox_group(namegroup)
            elif (command=='createrealm'):
                realm_id = j[1].strip()
                realm_address_target = j[2].strip()
                realm_port_target = j[3].strip()
                return self.createrealm(realm_id, realm_address_target, realm_port_target)
            elif (command=='ackrealm'):
                realm_id = j[1].strip()
                realm_address_target = j[2].strip()
                realm_port_target = j[3].strip()
                return self.acknowledgerealm(realm_id, realm_address_target, realm_port_target)
            elif (command=='listrealm'):
                return self.listrealm()
            elif (command=='sendrealm'):
                realm_id = j[1].strip()
                usernameto = j[2].strip()
                message=""
                for w in j[3:]:
                   message="{} {}" . format(message,w)
                message = message.lstrip()
                return self.sendrealmmessage(realm_id, usernameto, message)
            elif (command=='inboxrealm'):
                realm_id = j[1].strip()
                return self.inboxrealm(realm_id)
            elif (command=='makegrouprealm'):
                realm_id = j[1].strip()
                namegroup = j[2].strip()
                usergroups = ' '.join(j[3:])
                print(usergroups)
                return self.add_group_realm(realm_id,namegroup,usergroups)
            elif (command=='sendgrouprealm'):
                realm_id = j[1].strip()
                namegroup = j[2].strip()
                message=""
                for w in j[3:]:
                    message="{} {}" . format(message,w)
                return self.send_group_message_realm(realm_id,namegroup,message)
            elif (command=='inboxgrouprealm'):
                realm_id = j[1].strip()
                groupname = j[2].strip()
                return self.inboxgrouprealm(realm_id, groupname)
            elif (command=='recvgroupmsg'):
                realm_id = j[1].strip()
                groupname = j[2].strip()
                return self.recv_group_message_from_realm(realm_id, groupname)
            elif (command=='inbox'):
                return self.inbox()
            elif (command=='logout'):
                return self.logout()
            elif (command=='info'):
                return self.info()
            else:
                return "*Maaf, command tidak benar"
        except IndexError:
            return "-Maaf, command tidak benar"

    def sendstring(self,string):
        try:
            self.sock.sendall(string.encode())
            receivemsg = ""
            while True:
                data = self.sock.recv(1024)
                print("diterima dari server",data)
                if (data):
                    receivemsg = "{}{}" . format(receivemsg,data.decode())  #data harus didecode agar dapat di operasikan dalam bentuk string
                    if receivemsg[-4:]=='\r\n\r\n':
                        print("end of string")
                        return json.loads(receivemsg)
        except:
            self.sock.close()
            return { 'status' : 'ERROR', 'message' : 'Gagal'}

    def login(self,username,password):
        string="auth {} {} \r\n" . format(username,password)
        result = self.sendstring(string)
        if result['status']=='OK':
            self.tokenid=result['tokenid']
            return "username {} logged in, token {} " .format(username,self.tokenid)
        else:
            return "Error, {}" . format(result['message'])
    
    def register(self,username,password, nama, negara):
        string="register {} {} {} {}\r\n" . format(username,password, nama, negara)
        result = self.sendstring(string)
        if result['status']=='OK':
            self.tokenid=result['tokenid']
            return "username {} register in, token {} " .format(username,self.tokenid)
        else:
            return "Error, {}" . format(result['message'])

    def send_message(self,usernameto, message):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="send {} {} {} \r\n" . format(self.tokenid,usernameto,message)
        print(string)
        result = self.sendstring(string)
        if result['status']=='OK':
            return "message sent to {}" . format(usernameto)
        else:
            return "Error, {}" . format(result['message'])
    
    def add_group(self,group_name, user_group):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="addgroup {} {} {} \r\n" . format(self.tokenid,group_name, user_group)
        print(string)
        result = self.sendstring(string)
        if result['status']=='OK':
            return "group {} has been created, user: {} " . format(group_name, user_group)
        else:
            return "Error, {}" . format(result['message'])
        
    def send_group_message(self,usernames_to="xxx",message="xxx"):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="sendgroup {} {} {} \r\n" . format(self.tokenid,usernames_to,message)
        print(string)
        result = self.sendstring(string)
        if result['status']=='OK':
            return "message sent to group {}" . format(usernames_to)
        else:
            return "Error, {}" . format(result['message'])

    def inbox_group(self,namegroup):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="inboxgroup {} {} \r\n" . format(self.tokenid,namegroup)
        print(string)
        result = self.sendstring(string)
        if result['status']=='OK':
            return "message from group {}" . format(namegroup)
        else:
            return "Error, {}" . format(result['message'])
        
    def send_file(self, usernameto, filepath):
        if (self.tokenid==""):
            return "Error, not authorized"

        if not os.path.exists(filepath):
            return {'status': 'ERROR', 'message': 'File not found'}
        
        with open(filepath, 'rb') as file:
            file_content = file.read()
            encoded_content = base64.b64encode(file_content)  # Decode byte-string to UTF-8 string
        string="sendfile {} {} {} {}\r\n" . format(self.tokenid,usernameto,filepath,encoded_content)

        result = self.sendstring(string)
        if result['status']=='OK':
            return "file sent to {}" . format(usernameto)
        else:
            return "Error, {}" . format(result['message'])
               
    def acknowledgerealm(self, realm_id, realm_address, realm_port):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="ackrealm {} {} {} {} {}\r\n" . format(realm_id, IP_SERVER, PORT_SERVER, realm_address, realm_port)
        result = self.sendstring(string)
        if result['status']=='OK':
            return "connected realm {}" . format(realm_id)
        else:
            return "Error, {}" . format(result['message'])
            
    def createrealm(self, realm_id, realm_address, realm_port):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="createrealm {} {} {} {} {}\r\n" . format(realm_id, IP_SERVER, PORT_SERVER, realm_address, realm_port)
        result = self.sendstring(string)
        if result['status']=='OK':
            return "created realm {}" . format(realm_id)
        else:
            return "Error, {}" . format(result['message'])
        
    def listrealm(self):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="listrealm\r\n"
        result = self.sendstring(string)
        if result['status']=='OK':
            return "returned realm list: {}".format(json.dumps(result['message']))
        else:
            return "Error, {}" . format(result['message'])
        
    def sendrealmmessage(self, realm_id, usernameto, message):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="sendrealm {} {} {} {} {} {}\r\n" . format(IP_SERVER, PORT_SERVER, self.tokenid, realm_id, usernameto, message)
        result = self.sendstring(string)
        if result['status']=='OK':
            return "message sent to {} through realm {}" . format(usernameto, realm_id)
        else:
            return "Error, {}" . format(result['message'])
        
    def inboxrealm(self, realm_id):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="inboxrealm {} {}\r\n" . format(self.tokenid, realm_id)
        result = self.sendstring(string)
        if result['status']=='OK':
            return "{}" . format(json.dumps(result['messages']))
        else:
            return "Error, {}" . format(result['message'])
    
    def add_group_realm(self, realm_id, group_name, user_group):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="makegrouprealm {} {} {} {}\r\n" . format(self.tokenid, realm_id, group_name, user_group)
        print(string)
        result = self.sendstring(string)
        if result['status']=='OK':
            return "group {} has been created, user: {} " . format(group_name, user_group)
        else:
            return "Error, {}" . format(result['message'])
        
    def send_group_message_realm(self, realm_id, namegroup, message):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="sendgrouprealm {} {} {} {} \r\n" . format(self.tokenid, realm_id, namegroup, message)
        print(string)
        result = self.sendstring(string)
        if result['status']=='OK':
            return "message sent to group {}" . format(namegroup)
        else:
            return "Error, {}" . format(result['message'])
        
    def sendgrouprealmmessage(self, realm_id, groupname, message):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="sendgrouprealm {} {} {} {} {} {}\r\n" . format(IP_SERVER, PORT_SERVER, self.tokenid, realm_id, groupname, message)
        result = self.sendstring(string)
        if result['status']=='OK':
            return "group message sent to {} through realm {}" . format(groupname, realm_id)
        else:
            return "Error, {}" . format(result['message'])
        
    def inboxgrouprealm(self, realm_id, groupname):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="inboxgrouprealm {} {} {}\r\n" . format(self.tokenid, realm_id, groupname)
        print("\nini dari cli: ", string)
        result = self.sendstring(string)
        if result['status']=='OK':
            return "{}" . format(json.dumps(result['messages']))
        else:
            return "Error, {}" . format(result['message'])

    def recv_group_message_from_realm(self, realm_id, groupname):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="recvgroupmsg {} {} {}\r\n" . format(self.tokenid, realm_id, groupname)
        print("\nini dari cli: ", string)
        result = self.sendstring(string)
        if result['status']=='OK':
            return "{}" . format(json.dumps(result['messages']))
        else:
            return "Error, {}" . format(result['message'])

    def inbox(self):
        if (self.tokenid==""):
            return "Error, not authorized"
        string="inbox {} \r\n" . format(self.tokenid)
        result = self.sendstring(string)
        if result['status']=='OK':
            return "{}" . format(json.dumps(result['messages']))
        else:
            return "Error, {}" . format(result['message'])

    def logout(self):
        string="logout {}\r\n".format(self.tokenid)
        result = self.sendstring(string)
        if result['status']=='OK':
            self.tokenid=""
            return "Logout Berhasil"
        else:
            return "Error, {}" . format(result['message'])

    def info(self):
        string="info \r\n"
        result = self.sendstring(string)
        list_user_aktif="User yang Aktif:\n"
        if result['status']=='OK':
            list_user_aktif += f"{result['message']}"
        return list_user_aktif

if __name__=="__main__":
    cc = ChatClient()
    while True:
        cmdline = input("Command {}:" . format(cc.tokenid))
        print(cc.proses(cmdline))