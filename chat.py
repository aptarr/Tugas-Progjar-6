import sys
import os
import json
import uuid
import logging
from queue import  Queue
import threading
import socket
import base64
from datetime import datetime
from os.path import join, dirname, realpath
from collections import defaultdict

class RealmThreadCommunication(threading.Thread):
    def __init__(self, chats, realm_dest_address, realm_dest_port):
        self.chats = chats
        self.chat = {
            'users': {},
            'groups': {}
        }
        self.realm_dest_address = realm_dest_address
        self.realm_dest_port = realm_dest_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((self.realm_dest_address, self.realm_dest_port))
            threading.Thread.__init__(self)
        except:
            return None

    def sendstring(self, string):
        try:
            self.sock.sendall(string.encode())
            receivedmsg = ""
            while True:
                data = self.sock.recv(1024)
                print("diterima dari server", data)
                if (data):
                    receivedmsg = "{}{}" . format(receivedmsg, data.decode())
                    if receivedmsg[-4:]=='\r\n\r\n':
                        print("end of string")
                        return json.loads(receivedmsg)
        except:
            self.sock.close()
            return {'status': 'ERROR', 'message': 'Gagal'}
        
    def put_private(self, message):
        dest = message['msg_to']
        try:
            self.chat['users'][dest].put(message)
        except KeyError:
            self.chat['users'][dest] = Queue()
            self.chat['users'][dest].put(message)

    def make_group(self, groupname, usernames):
        if groupname in self.chat['groups']:
            return {'status': 'ERROR', 'message': 'Group Name Sudah Digunakan'}
        self.chat['groups'][groupname] = {'members': usernames, 'queue': Queue()}
        return {'status': 'OK', 'message': 'Group Created'}

    def send_group_message(self, username_from, realm_id, groupname, message):
        if groupname not in self.chat['groups']:
            return {'status': 'ERROR', 'message': 'Group Tidak Ditemukan'}
        
        # print("ini pesan di realm:", message)
        
        group = self.chat['groups'][groupname]
        print("ini group di realm:", group)
        if username_from not in group['members']:
            return {'status': 'ERROR', 'message': 'User Bukan Member Group'}
        
        msg = {'msg_from': username_from, 'msg_to_group': groupname, 'msg': message}
        group['queue'].put(msg)  # Put the message in the group's queue
        
        # print("ini msg di realm:", msg)
        return {'status': 'OK', 'message': 'Message Sent to Group'}

    def get_realm_group_inbox(self, groupname):
        logging.info("Fetching group inbox for group: {}".format(groupname))
        if groupname not in self.chat['groups']:
            logging.warning("Group {} not found in realm groups.".format(groupname))
            return {'status': 'ERROR', 'message': 'Group Tidak Ditemukan'}
        
        group = self.chat['groups'][groupname]
        msgs = []
        try:
            while not group['queue'].empty():
                msgs.append(group['queue'].get_nowait())
        except Exception as e:
            logging.error("Error retrieving group inbox: {}".format(str(e)))
            return {'status': 'ERROR', 'message': 'Error retrieving group inbox'}
    
        logging.info("Retrieved messages for group {}: {}".format(groupname, msgs))
        return {'status': 'OK', 'messages': msgs}


class Chat:
    def __init__(self):
        self.sessions = {}
        self.users = {}
        self.groups = {}
        self.realms = {}
        self.realms_info = {}

        # Example users
        self.users['messi'] = {'nama': 'Lionel Messi', 'negara': 'Argentina', 'password': 'surabaya', 'incoming': defaultdict(Queue), 'outgoing': defaultdict(Queue), 'group_inbox': defaultdict(Queue)}
        self.users['henderson'] = {'nama': 'Jordan Henderson', 'negara': 'Inggris', 'password': 'surabaya', 'incoming': defaultdict(Queue), 'outgoing': defaultdict(Queue), 'group_inbox': defaultdict(Queue)}
        self.users['lineker'] = {'nama': 'Gary Lineker', 'negara': 'Inggris', 'password': 'surabaya', 'incoming': defaultdict(Queue), 'outgoing': defaultdict(Queue), 'group_inbox': defaultdict(Queue)}

        # Add users to each realm
        for realm in self.realms.values():
            for username, user_info in self.users.items():
                realm.chat['users'][username] = user_info

    def proses(self, data):
        j = data.split(" ")
        try:
            command = j[0].strip()
            if command == 'auth':
                username = j[1].strip()
                password = j[2].strip()
                logging.warning("AUTH: auth {} {}".format(username, password))
                return self.autentikasi_user(username, password)
            elif command == "register":
                username = j[1].strip()
                password = j[2].strip()
                nama = j[3].strip()
                negara = j[4].strip()
                logging.warning("REGISTER: register {} {}".format(username, password))
                return self.register_user(username, password, nama, negara)
            elif command == 'send':
                sessionid = j[1].strip()
                usernameto = j[2].strip()
                message = " ".join(j[3:])
                usernamefrom = self.sessions[sessionid]['username']
                logging.warning("SEND: session {} send message from {} to {}".format(sessionid, usernamefrom, usernameto))
                return self.send_message(sessionid, usernamefrom, usernameto, message)
            elif command == 'inbox':
                sessionid = j[1].strip()
                username = self.sessions[sessionid]['username']
                logging.warning("INBOX: {}".format(sessionid))
                return self.get_inbox(username)
            elif command == 'addgroup':
                sessionid = j[1].strip()
                groupname = j[2].strip()
                usernames = [user.strip() for user in j[3:] if user.strip()]
                logging.warning("ADDGROUP: session {} add group {} with users {}".format(sessionid, groupname, usernames))
                return self.add_group(sessionid, groupname, usernames)
            elif command == 'sendgroup':
                sessionid = j[1].strip()
                groupname = j[2].strip()
                message = " ".join(j[3:])
                usernamefrom = self.sessions[sessionid]['username']
                logging.warning("SENDGROUP: session {} send message from {} to group {}".format(sessionid, usernamefrom, groupname))
                return self.send_group_message(sessionid, usernamefrom, groupname, message)
            elif command == 'listgroup':
                sessionid = j[1].strip()
                logging.warning("LISTGROUP: session {}".format(sessionid))
                return self.list_group(sessionid)
            elif command == 'inboxgroup':
                sessionid = j[1].strip()
                groupname = j[2].strip()
                logging.warning("INBOXGROUP: session {} group {}".format(sessionid, groupname))
                return self.get_inbox_group(sessionid, groupname)
            elif (command == 'createrealm'):
                realm_id = j[1].strip()
                realm_address = j[2].strip()
                realm_port = int(j[3].strip())
                src_address = j[4].strip()
                src_port = int(j[5].strip())
                logging.warning("CREATE REALM: {}:{} create realm {} to {}:{}" . format(src_address, src_port, realm_id, realm_address, realm_port))
                return self.create_realm(realm_id, realm_address, realm_port, src_address, src_port)
            elif (command == 'ackrealm'):
                realm_id = j[1].strip()
                realm_address = j[2].strip()
                realm_port = int(j[3].strip())
                src_address = j[4].strip()
                src_port = int(j[5].strip())
                logging.warning("ACK REALM: {}:{} received realm {} connection request from {}:{}" . format(realm_id, realm_address, realm_port, src_address, src_port))
                return self.ack_realm(realm_id, src_address, src_port)
            elif (command == 'listrealm'):
                logging.warning("LIST REALM")
                return self.list_realm()
            elif (command == 'sendrealm'):
                src_address = j[1].strip()
                src_port = j[2].strip()
                sessionid = j[3].strip()
                realm_id = j[4].strip()
                usernameto = j[5].strip()
                message=""
                for w in j[6:]:
                    message="{} {}" . format(message,w)
                usernamefrom = self.sessions[sessionid]['username']
                logging.warning("SEND REALM: session {} send message from {} to {} through realm {}" . format(sessionid, usernamefrom, usernameto, realm_id))
                return self.send_realm(sessionid, src_address, src_port, realm_id, usernamefrom, usernameto, message)
            elif (command == 'inboxrealm'):
                sessionid = j[1].strip()
                realm_id = j[2].strip()
                username = self.sessions[sessionid]['username']
                logging.warning("INBOX REALM: session {} username {} realm {}" . format(sessionid, username, realm_id))
                return self.get_realm_inbox(sessionid, username, realm_id)
            elif (command == 'rcvinboxrealm'):
                username = j[1].strip()
                realm_id = j[2].strip()
                logging.warning("RECEIVE INBOX REALM: username {} realm {}" . format(username, realm_id))
                return self.rcv_realm_inbox(username, realm_id)
            elif (command == 'makegrouprealm'):
                sessionid = j[1].strip()
                realm_id = j[2].strip()
                groupname = j[3].strip()
                usernames = [user.strip() for user in j[4:] if user.strip()]
                logging.warning("MAKE GROUP REALM: session {} create group {} in realm {} with users {}".format(sessionid, groupname, realm_id, usernames))
                return self.make_group_realm(sessionid, realm_id, groupname, usernames)
            elif (command == 'sendgrouprealm'):
                sessionid = j[1].strip()
                realm_id = j[2].strip()
                groupname = j[3].strip()
                message = " ".join(j[4:])
                usernamefrom = self.sessions[sessionid]['username']
                logging.warning("SEND GROUP REALM: session {} send message from {} to group {} in realm {}".format(sessionid, usernamefrom, groupname, realm_id))
                return self.send_group_message_realm(usernamefrom, realm_id, groupname, message)
            elif command == 'inboxgrouprealm':
                sessionid = j[1].strip()
                realm_id = j[2].strip()
                groupname = j[3].strip()
                username = self.sessions[sessionid]['username']
                logging.warning("INBOX GROUP REALM: session {}, username: {}, groupname: {}, realm: {}" . format(sessionid, username, groupname, realm_id))
                return self.inbox_get_realm_group(sessionid, realm_id, groupname)
            elif (command == 'rcvinboxgrouprealm'):
                realm_id = j[1].strip()
                groupname = j[2].strip()
                logging.warning("RECEIVE INBOX GROUP REALM: groupname {} realm {}" . format(groupname, realm_id))
                print("masuk rcvrealm")
                return self.rcv_realm_group_inbox(realm_id, groupname)
            else:
                return {'status': 'ERROR', 'message': 'Protocol Tidak Benar'}
        except KeyError:
            return {'status': 'ERROR', 'message': 'Informasi tidak ditemukan'}
        except IndexError:
            return {'status': 'ERROR', 'message': 'Protocol Tidak Benar'}

    def autentikasi_user(self, username, password):
        if username not in self.users:
            return {'status': 'ERROR', 'message': 'User Tidak Ada'}
        if self.users[username]['password'] != password:
            return {'status': 'ERROR', 'message': 'Password Salah'}
        tokenid = str(uuid.uuid4())
        self.sessions[tokenid] = {'username': username, 'userdetail': self.users[username]}
        return {'status': 'OK', 'tokenid': tokenid}

    def register_user(self, username, password, nama, negara):
        if username in self.users:
            return {'status': 'ERROR', 'message': 'Username Sudah Digunakan'}

        self.users[username] = {
            'password': password,
            'nama': nama,
            'negara': negara,
            'incoming': defaultdict(Queue),
            'outgoing': defaultdict(Queue),
            'group_inbox': defaultdict(Queue)
        }
        return {'status': 'OK', 'message': 'User Terdaftar'}

    def get_user(self, username):
        if username not in self.users:
            return False
        return self.users[username]
    
    def get_group(self, groupname):
        if groupname in self.groups:
            return self.groups[groupname]
        else:
            return False

    def send_message(self, sessionid, username_from, username_dest, message):
        if sessionid not in self.sessions:
            return {'status': 'ERROR', 'message': 'Session Tidak Ditemukan'}
        s_fr = self.get_user(username_from)
        s_to = self.get_user(username_dest)

        if not s_fr or not s_to:
            return {'status': 'ERROR', 'message': 'User Tidak Ditemukan'}

        message = {'msg_from': s_fr['nama'], 'msg_to': s_to['nama'], 'msg': message}
        outqueue_sender = s_fr['outgoing']
        inqueue_receiver = s_to['incoming']
        
        try:
            outqueue_sender[username_dest].put(message)
        except KeyError:
            outqueue_sender[username_dest] = Queue()
            outqueue_sender[username_dest].put(message)

        try:
            inqueue_receiver[username_from].put(message)
        except KeyError:
            inqueue_receiver[username_from] = Queue()
            inqueue_receiver[username_from].put(message)

        return {'status': 'OK', 'message': 'Message Sent'}
        
    def get_inbox(self, username):
        s_fr = self.get_user(username)
        incoming = s_fr['incoming']
        msgs = {}
        for user, queue in incoming.items():
            msgs[user] = []
            while not queue.empty():
                msgs[user].append(queue.get())
        return {'status': 'OK', 'messages': msgs}

    def add_group(self, sessionid, groupname, usernames):
        if sessionid not in self.sessions:
            return {'status': 'ERROR', 'message': 'Session Tidak Ditemukan'}
        
        usernames = [user.strip() for user in usernames]
        
        s_fr = self.sessions[sessionid]['username']
        
        if groupname in self.groups:
            return {'status': 'ERROR', 'message': 'Group Name Sudah Digunakan'}
        self.groups[groupname] = usernames
        return {'status': 'OK', 'message': 'Group Created'}
    
    def send_group_message(self, sessionid, username_from, group_name, message):
        if sessionid not in self.sessions:
            return {'status': 'ERROR', 'message': 'Session Tidak Ditemukan'}
        s_fr = self.get_user(username_from)
        if s_fr == False:
            return {'status': 'ERROR', 'message': 'User Tidak Ditemukan'}

        if group_name not in self.groups:
            return {'status': 'ERROR', 'message': 'Group Tidak Ditemukan'}

        users_in_group = self.groups[group_name]
        message = {'msg_from': s_fr['nama'], 'msg_to_group': group_name, 'msg': message}
        for user in users_in_group:
            s_to = self.get_user(user)
            inqueue_receiver = s_to['group_inbox'][group_name]
            inqueue_receiver.put(message)
        return {'status': 'OK', 'message': 'Message Sent to Group'}

    def list_group(self, sessionid):
        if sessionid not in self.sessions:
            return {'status': 'ERROR', 'message': 'Session Tidak Ditemukan'}
        return {'status': 'OK', 'groups': list(self.groups.keys())}

    def get_inbox_group(self, sessionid, groupname):
        if sessionid not in self.sessions:
            return {'status': 'ERROR', 'message': 'Session Tidak Ditemukan'}
        username = self.sessions[sessionid]['username']
        s_fr = self.get_user(username)
        group_inbox = s_fr['group_inbox'][groupname]
        msgs = []
        while not group_inbox.empty():
            msgs.append(group_inbox.get_nowait())
        return {'status': 'OK', 'messages': msgs}

    def create_realm(self, realm_id, realm_address, realm_port, src_address, src_port):
        if (realm_id in self.realms_info):
            return { 'status': 'ERROR', 'message': 'Realm sudah ada' }
            
        self.realms[realm_id] = RealmThreadCommunication(self, realm_address, realm_port)
        result = self.realms[realm_id].sendstring("ackrealm {} {} {} {} {}\r\n" . format(realm_id, realm_address, realm_port, src_address, src_port))
        if result['status']=='OK':
            self.realms_info[realm_id] = {'serverip': realm_address, 'port': realm_port}
            return result
        else:
            return {'status': 'ERROR', 'message': 'Realm unreachable'}

    def ack_realm(self, realm_id, src_address, src_port):
        self.realms[realm_id] = RealmThreadCommunication(self, src_address, src_port)
        self.realms_info[realm_id] = {'serverip': src_address, 'port': src_port}
        return {'status': 'OK', 'message': 'Connect realm berhasil'}

    def list_realm(self):
        return {'status': 'OK', 'message': self.realms_info}

    def send_realm(self, sessionid, src_address, src_port, realm_id, usernamefrom, usernameto, message):
        if (sessionid not in self.sessions):
            return {'status': 'ERROR', 'message': 'Session Tidak Ditemukan'}
        if (realm_id not in self.realms_info):
            return {'status': 'ERROR', 'message': 'Realm Tidak Ditemukan'}

        s_fr = self.get_user(usernamefrom)
        s_to = self.get_user(usernameto)
        
        if (s_fr==False or s_to==False):
            return {'status': 'ERROR', 'message': 'User Tidak Ditemukan'}

        msg_from = f"{s_fr['nama']} ({src_address}:{src_port})"
        message = {'msg_from': msg_from, 'msg_to': s_to['nama'], 'msg': message}
        self.realms[realm_id].put_private(message)

        logging.warning("Sending message: {}".format(message))
        
        return {'status': 'OK', 'message': 'Realm Private Message Sent'}

    def get_realm_inbox(self, sessionid, username, realm_id):
        if (sessionid not in self.sessions):
            return {'status': 'ERROR', 'message': 'Session Tidak Ditemukan'}
        if (realm_id not in self.realms_info):
            return { 'status': 'ERROR', 'message': 'Realm Tidak Ditemukan' }

        logging.warning("Fetching inbox for user {} in realm {}".format(username, realm_id))
        return self.realms[realm_id].sendstring("rcvinboxrealm {} {}\r\n".format(username, realm_id))

    def rcv_realm_inbox(self, username, realm_id):
        if (realm_id not in self.realms_info):
            return { 'status': 'ERROR', 'message': 'Realm Tidak Ditemukan' }
        s_fr = self.get_user(username)
        msgs = []
        q = self.realms[realm_id].chat['users'][s_fr['nama']].queue.copy()
        while len(q) > 0:
            msgs.append(q.pop())
        return {'status': 'OK', 'messages': msgs}

    def make_group_realm(self, sessionid, realm_id, groupname, usernames):
        if realm_id not in self.realms:
            return {'status': 'ERROR', 'message': 'Realm Tidak Ditemukan'}
        
        realm_thread = self.realms[realm_id]

        # Ensure all users exist in the realm
        for username in usernames:
            if username not in realm_thread.chat['users']:
                if username in self.users:
                    realm_thread.chat['users'][username] = self.users[username]
                else:
                    return {'status': 'ERROR', 'message': f'User {username} Tidak Ditemukan'}

        return realm_thread.make_group(groupname, usernames)

    def send_group_message_realm(self, username_from, realm_id, groupname, message):
        if realm_id not in self.realms:
            return {'status': 'ERROR', 'message': 'Realm Tidak Ditemukan'}
        realm_thread = self.realms[realm_id]
        print ("ini pesan:", message)
        result = realm_thread.send_group_message(username_from, realm_id, groupname, message)
        print("Result from send_group_message:", result)  # Debugging print
        
        return result
    # return realm_thread.send_group_message(username_from, realm_id, groupname, message)

    def inbox_get_realm_group(self, sessionid, realm_id, groupname):
        if (sessionid not in self.sessions):
            return {'status': 'ERROR', 'message': 'Session Tidak Ditemukan'}
        if (realm_id not in self.realms_info):
            return {'status': 'ERROR', 'message': 'Realm Tidak Ditemukan'}

        realm_thread = self.realms[realm_id]
        print("masuk box realm: ", realm_thread)
        return self.realms[realm_id].sendstring("rcvinboxgrouprealm {} {}\r\n".format(realm_id, groupname))
    
        # realm_thread = self.realms[realm_id]
        # return realm_thread.get_realm_group_inbox(groupname)

    def rcv_realm_group_inbox(self, realm_id, groupname):
        if realm_id not in self.realms_info:
            return {'status': 'ERROR', 'message': 'Realm Tidak Ditemukan'}
    
        realm_thread = self.realms[realm_id]
        group = realm_thread.chat['groups'].get(groupname)
    
        if not group:
            return {'status': 'ERROR', 'message': 'Group Tidak Ditemukan'}
    
        msgs = []
        while not group['queue'].empty():
            msgs.append(group['queue'].get_nowait())
    
        return {'status': 'OK', 'messages': msgs}

if __name__ == "__main__":
    j = Chat()
    sesi = j.proses("auth messi surabaya")
    sesi2 = j.proses("auth henderson surabaya")
    print(sesi)
    print(sesi2)

    tokenid = sesi['tokenid']
    tokenid2 = sesi2['tokenid']
    print(j.proses("send {} henderson hello gimana kabarnya son " . format(tokenid)))
    print(j.proses("send {} messi hello gimana kabarnya mess " . format(tokenid)))

    print(j.proses("addgroup {} grupbaru messi henderson" . format(tokenid)))
    print(j.proses("listgroup {}".format(tokenid)))
    print(j.proses("sendgroup {} grupbaru hello grupbaru!".format(tokenid)))
    print(j.proses("inboxgroup {} grupbaru".format(tokenid)))
    print(j.proses("sendgroup {} grupbaru hello grupbaru!".format(tokenid2)))
    print(j.proses("inboxgroup {} grupbaru".format(tokenid2)))

    print("\nisi mailbox dari messi")
    print(j.get_inbox('messi'))
    print("isi mailbox dari henderson")
    print(j.get_inbox('henderson'))

    # print(j.proses("addrealm myrealm 172.16.16.101 8889 172.16.16.102 8000"))