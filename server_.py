import socket
import threading
import mysql.connector
from mysql.connector import Error
import json
import time

class ChatServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen()
        self.clients = {}
        self.db_connection = self.create_db_connection()

    def create_db_connection(self):
        try:
            connection = mysql.connector.connect(
                host='localhost',
                user='root',
                password='',
                database=''
            )
            return connection
        except Error as e:
            print(f"Error connecting to MySQL: {e}")
            return None

    def send_json(self, client_socket, data):
        json_data = json.dumps(data)
        message = json_data + "\n"
        client_socket.sendall(message.encode('utf-8'))

    def handle_client(self, client, address):
        buffer = ""
        try:
            while True:
                chunk = client.recv(4096).decode('utf-8')
                if not chunk:
                    break

                buffer += chunk
                messages = buffer.split('\n')
                buffer = messages.pop()

                for message in messages:
                    if message:
                        try:
                            data = json.loads(message)

                            if 'action' in data:
                                if data['action'] == 'register':
                                    success = self.register_user(data['username'], data['password'])
                                    response = {'status': 'success' if success else 'fail', 'action': 'register',
                                                'message': 'Registration successful' if success else 'Username already exists'}
                                    self.send_json(client, response)
                                    if not success:
                                        return

                                elif data['action'] == 'login':
                                    success = self.authenticate_user(data['username'], data['password'])
                                    response = {'status': 'success' if success else 'fail', 'action': 'login',
                                                'message': 'Login successful' if success else 'Invalid username or password'}
                                    self.send_json(client, response)
                                    if not success:
                                        return

                                username = data['username']
                                self.clients[username] = (client, address)
                                self.update_user_status(username, True)
                                self.send_pending_messages(username)
                                self.send_user_list(username)

                            elif 'type' in data:
                                if 'username' not in locals():
                                    continue

                                if data['type'] == 'message':
                                    self.handle_private_message(username, data)
                                elif data['type'] == 'get_users':
                                    self.send_user_list(username)
                                elif data['type'] == 'get_history':
                                    self.send_message_history(username, data['with_user'])

                        except json.JSONDecodeError as e:
                            print(f"JSON decode error: {e}, message: {message[:50]}...")

            if 'username' in locals():
                self.handle_client_disconnect(username)

        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            if 'username' in locals():
                self.handle_client_disconnect(username)
            else:
                try:
                    client.close()
                except:
                    pass

    def send_message_history(self, requesting_user, with_user):
        try:
            cursor = self.db_connection.cursor(dictionary=True)
            query = """
                SELECT 
                    m.message_id, 
                    s.username as sender, 
                    r.username as receiver,
                    m.message_text,
                    m.timestamp,
                    m.is_read
                FROM messages m
                JOIN users s ON m.sender_id = s.user_id
                JOIN users r ON m.receiver_id = r.user_id
                WHERE (s.username = %s AND r.username = %s)
                   OR (s.username = %s AND r.username = %s)
                ORDER BY m.timestamp
            """
            cursor.execute(query, (requesting_user, with_user, with_user, requesting_user))
            messages = cursor.fetchall()

            if requesting_user in self.clients:
                client_socket, _ = self.clients[requesting_user]
                history = {
                    'type': 'message_history',
                    'with_user': with_user,
                    'messages': [
                        {
                            'sender': msg['sender'],
                            'receiver': msg['receiver'],
                            'message': msg['message_text'],
                            'timestamp': msg['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                            'is_read': msg['is_read']
                        }
                        for msg in messages
                    ]
                }
                self.send_json(client_socket, history)

        except Error as e:
            print(f"Error retrieving message history: {e}")
        finally:
            if 'cursor' in locals():
                cursor.close()

    def handle_private_message(self, sender, message_data):
        receiver = message_data['receiver']
        message_text = message_data['message']

        self.store_message(sender, receiver, message_text)

        if receiver in self.clients:
            self.mark_message_as_read(sender, receiver)
            receiver_socket, _ = self.clients[receiver]
            message_to_send = {
                'type': 'message',
                'sender': sender,
                'message': message_text,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            self.send_json(receiver_socket, message_to_send)

        if sender in self.clients:
            sender_socket, _ = self.clients[sender]
            confirmation = {
                'type': 'delivery',
                'receiver': receiver,
                'status': 'delivered' if receiver in self.clients else 'pending'
            }
            self.send_json(sender_socket, confirmation)

    def send_pending_messages(self, username):
        try:
            cursor = self.db_connection.cursor(dictionary=True)
            query = """
                SELECT m.message_id, u.username as sender, m.message_text, m.timestamp
                FROM messages m
                JOIN users u ON m.sender_id = u.user_id
                JOIN users r ON m.receiver_id = r.user_id
                WHERE r.username = %s AND m.is_read = FALSE
                ORDER BY m.timestamp
            """
            cursor.execute(query, (username,))
            pending_messages = cursor.fetchall()

            if pending_messages and username in self.clients:
                client_socket, _ = self.clients[username]

                for message in pending_messages:
                    message_data = {
                        'type': 'message',
                        'sender': message['sender'],
                        'message': message['message_text'],
                        'timestamp': message['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                        'pending': True
                    }
                    self.send_json(client_socket, message_data)

                self.mark_messages_as_read(username)

        except Error as e:
            print(f"Error retrieving pending messages: {e}")
        finally:
            if 'cursor' in locals():
                cursor.close()

    def mark_messages_as_read(self, receiver_username):
        try:
            cursor = self.db_connection.cursor()
            query = """
                UPDATE messages m
                JOIN users r ON m.receiver_id = r.user_id
                SET m.is_read = TRUE
                WHERE r.username = %s AND m.is_read = FALSE
            """
            cursor.execute(query, (receiver_username,))
            self.db_connection.commit()
        except Error as e:
            print(f"Error marking messages as read: {e}")
        finally:
            if 'cursor' in locals():
                cursor.close()

    def mark_message_as_read(self, sender_username, receiver_username):
        try:
            cursor = self.db_connection.cursor()
            query = """
                UPDATE messages m
                JOIN users s ON m.sender_id = s.user_id
                JOIN users r ON m.receiver_id = r.user_id
                SET m.is_read = TRUE
                WHERE s.username = %s AND r.username = %s AND m.is_read = FALSE
            """
            cursor.execute(query, (sender_username, receiver_username))
            self.db_connection.commit()
        except Error as e:
            print(f"Error marking message as read: {e}")
        finally:
            if 'cursor' in locals():
                cursor.close()

    def store_message(self, sender, receiver, message_text):
        try:
            cursor = self.db_connection.cursor()
            cursor.execute("SELECT user_id FROM users WHERE username = %s", (sender,))
            sender_id = cursor.fetchone()[0]
            cursor.execute("SELECT user_id FROM users WHERE username = %s", (receiver,))
            receiver_id = cursor.fetchone()[0]
            insert_query = """
                INSERT INTO messages (sender_id, receiver_id, message_text, is_read)
                VALUES (%s, %s, %s, %s)
            """
            is_read = receiver in self.clients
            cursor.execute(insert_query, (sender_id, receiver_id, message_text, is_read))
            self.db_connection.commit()
        except Error as e:
            print(f"Error storing message: {e}")
        finally:
            if 'cursor' in locals():
                cursor.close()

    def send_user_list(self, requesting_user):
        try:
            cursor = self.db_connection.cursor(dictionary=True)
            cursor.execute("SELECT username, online_status FROM users")
            users = cursor.fetchall()
            for user in users:
                user['online_status'] = user['username'] in self.clients

            if requesting_user in self.clients:
                client_socket, _ = self.clients[requesting_user]
                user_list = {
                    'type': 'user_list',
                    'users': [{'username': u['username'], 'online': u['online_status']} for u in users]
                }
                self.send_json(client_socket, user_list)

        except Error as e:
            print(f"Error retrieving user list: {e}")
        finally:
            if 'cursor' in locals():
                cursor.close()

    def register_user(self, username, password):
        try:
            cursor = self.db_connection.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
            self.db_connection.commit()
            return True
        except Error as e:
            print(f"Error registering user: {e}")
            return False
        finally:
            if 'cursor' in locals():
                cursor.close()

    def authenticate_user(self, username, password):
        try:
            cursor = self.db_connection.cursor(dictionary=True)
            cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
            result = cursor.fetchone()
            return result and result['password'] == password
        except Error as e:
            print(f"Error authenticating user: {e}")
            return False
        finally:
            if 'cursor' in locals():
                cursor.close()

    def update_user_status(self, username, online):
        try:
            cursor = self.db_connection.cursor()
            cursor.execute("UPDATE users SET online_status = %s WHERE username = %s", (online, username))
            self.db_connection.commit()
        except Error as e:
            print(f"Error updating user status: {e}")
        finally:
            if 'cursor' in locals():
                cursor.close()

    def handle_client_disconnect(self, username):
        if username in self.clients:
            client_socket, _ = self.clients[username]
            try:
                client_socket.close()
            except:
                pass
            del self.clients[username]
            self.update_user_status(username, False)
            print(f"{username} disconnected")

    def start(self):
        print(f"Server started on {self.host}:{self.port}")
        try:
            while True:
                client, address = self.server.accept()
                print(f"New connection from {address}")
                thread = threading.Thread(target=self.handle_client, args=(client, address))
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            print("Shutting down server...")
            for username, (client, _) in list(self.clients.items()):
                try:
                    client.close()
                except:
                    pass
                self.update_user_status(username, False)
            self.server.close()
            if self.db_connection:
                self.db_connection.close()

if __name__ == "__main__":
    server = ChatServer()
    server.start()

