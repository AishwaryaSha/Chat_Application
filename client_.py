import socket
import threading
import json
import tkinter as tk
from tkinter import scrolledtext, messagebox
from datetime import datetime

class ChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Chat Application")
        self.username = None
        self.client_socket = None
        self.connected = False
        self.receive_thread = None
        self.buffer = ""  

        self.setup_login_ui()
        
    def setup_login_ui(self):
        self.clear_window()
        self.master.geometry("300x200")
        tk.Label(self.master, text="Username:").pack(pady=(20, 0))
        self.username_entry = tk.Entry(self.master)
        self.username_entry.pack(pady=5)
        tk.Label(self.master, text="Password:").pack()
        self.password_entry = tk.Entry(self.master, show="*")
        self.password_entry.pack(pady=5)
        button_frame = tk.Frame(self.master)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Login", command=self.login).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Register", command=self.register).pack(side=tk.LEFT, padx=5)
    
    def setup_chat_ui(self):
        self.clear_window()
        self.master.geometry("800x600")
        self.user_list_frame = tk.Frame(self.master, width=200, bg='#f0f0f0')
        self.user_list_frame.pack(side=tk.LEFT, fill=tk.Y)
        tk.Button(self.user_list_frame, text="Refresh", command=self.refresh).pack(pady=5)
        tk.Label(self.user_list_frame, text="Online Users", bg='#f0f0f0', font=('Arial', 12, 'bold')).pack(pady=10)
        self.users_listbox = tk.Listbox(self.user_list_frame)
        self.users_listbox.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)
        self.users_listbox.bind('<<ListboxSelect>>', self.on_user_select)

        self.chat_frame = tk.Frame(self.master)
        self.chat_frame.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH)
        self.chat_display = scrolledtext.ScrolledText(self.chat_frame, state='disabled')
        self.chat_display.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

        self.message_entry = tk.Entry(self.chat_frame)
        self.message_entry.pack(fill=tk.X, padx=5, pady=5)
        self.message_entry.bind('<Return>', self.send_message)
        tk.Button(self.chat_frame, text="Send", command=self.send_message).pack(side=tk.RIGHT, padx=5, pady=5)
        self.current_chat_label = tk.Label(self.chat_frame, text="Select a user to chat with", font=('Arial', 10))
        self.current_chat_label.pack(side=tk.LEFT, padx=5)
        self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receive_thread.start()
        self.request_user_list()
    
    def refresh(self):
        if self.connected:
            self.request_user_list()
            if hasattr(self, 'selected_user'):
                self.chat_display.config(state='normal')
                self.chat_display.delete(1.0, tk.END)
                self.chat_display.config(state='disabled')
                request = {
                    'type': 'get_history',
                    'with_user': self.selected_user
                }
                try:
                    self.send_json(request)
                except Exception as e:
                    print(f"Error requesting message history: {e}")
            self.chat_display.config(state='normal')
            self.chat_display.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] System: Refreshed all data\n", "status")
            self.chat_display.tag_config("status", foreground="gray")
            self.chat_display.config(state='disabled')
            self.chat_display.see(tk.END)
    
    def clear_window(self):
        for widget in self.master.winfo_children():
            widget.destroy()
    
    def connect_to_server(self):
        try:
            if self.client_socket:
                self.client_socket.close()
                
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(5)  
            self.client_socket.connect(('localhost', 5555))
            self.client_socket.settimeout(None)  
            self.connected = True
            self.buffer = ""  
            return True
        except socket.timeout:
            messagebox.showerror("Connection Error", "Connection to server timed out")
        except ConnectionRefusedError:
            messagebox.showerror("Connection Error", "Server is not running or unavailable")
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect to server: {str(e)}")
        return False
    
    def send_json(self, data):
        json_data = json.dumps(data)
        message = json_data + "\n" 
        self.client_socket.sendall(message.encode('utf-8'))
    
    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()       
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return      
        if not self.connect_to_server():
            return
        
        login_data = {
            'action': 'login',
            'username': username,
            'password': password
        }
        
        try:
            self.send_json(login_data)
            self.client_socket.settimeout(5)
            response = self.client_socket.recv(4096).decode('utf-8')
            self.client_socket.settimeout(None)
            if not response:
                messagebox.showerror("Login Failed", "Empty response from server")
                return
            responses = response.strip().split('\n')
            for resp in responses:
                if resp:
                    try:
                        response_data = json.loads(resp)
                        if response_data.get('action') == 'login':
                            if response_data.get('status') == 'success':
                                self.username = username
                                self.setup_chat_ui()
                                return
                            else:
                                messagebox.showerror("Login Failed", response_data.get('message', 'Invalid username or password'))
                                return
                    except json.JSONDecodeError:
                        continue
                        
            messagebox.showerror("Login Failed", "Invalid server response")    
        except json.JSONDecodeError:
            messagebox.showerror("Login Failed", "Invalid server response format")
        except socket.timeout:
            messagebox.showerror("Login Failed", "Server response timeout")
        except Exception as e:
            messagebox.showerror("Error", f"Login failed: {str(e)}")
            if self.client_socket:
                self.client_socket.close()
                self.connected = False
    
    def register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()       
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return
        
        if not self.connect_to_server():
            return
        
        register_data = {
            'action': 'register',
            'username': username,
            'password': password
        }
        
        try:
            self.send_json(register_data)
            self.client_socket.settimeout(5)
            response = self.client_socket.recv(4096).decode('utf-8')
            self.client_socket.settimeout(None) 
            if not response:
                messagebox.showerror("Registration Failed", "Empty response from server")
                return
            responses = response.strip().split('\n')
            for resp in responses:
                if resp:
                    try:
                        response_data = json.loads(resp)
                        if response_data.get('action') == 'register':
                            if response_data.get('status') == 'success':
                                messagebox.showinfo("Success", "Registration successful. Please login.")
                                return
                            else:
                                messagebox.showerror("Registration Failed", response_data.get('message', 'Registration failed'))
                                return
                    except json.JSONDecodeError:
                        continue
                        
            messagebox.showerror("Registration Failed", "Invalid server response")
            
        except json.JSONDecodeError:
            messagebox.showerror("Registration Failed", "Invalid server response format")
        except socket.timeout:
            messagebox.showerror("Registration Failed", "Server response timeout")
        except Exception as e:
            messagebox.showerror("Error", f"Registration failed: {str(e)}")
        finally:
            if self.client_socket:
                self.client_socket.close()
                self.connected = False
    
    def request_user_list(self):
        if self.connected:
            try:
                request = {'type': 'get_users'}
                self.send_json(request)
            except Exception as e:
                print(f"Error requesting user list: {e}")
    
    def on_user_select(self, event):
        selection = event.widget.curselection()
        if selection:
            index = selection[0]
            selected_text = event.widget.get(index)
            if selected_text.startswith("Last updated:"):
                return
            self.selected_user = selected_text.split(' (')[0]
            self.current_chat_label.config(text=f"Chatting with: {self.selected_user}")
            self.chat_display.config(state='normal')
            self.chat_display.delete(1.0, tk.END)
            self.chat_display.config(state='disabled')
            request = {
                'type': 'get_history',
                'with_user': self.selected_user
            }
            try:
                self.send_json(request)
            except Exception as e:
                print(f"Error requesting message history: {e}")
    
    def send_message(self, event=None):
        if not hasattr(self, 'selected_user'):
            messagebox.showwarning("No Selection", "Please select a user to chat with")
            return
        message_text = self.message_entry.get().strip()
        if not message_text:
            return
        
        message_data = {
            'type': 'message',
            'receiver': self.selected_user,
            'message': message_text
        }
        
        try:
            self.send_json(message_data)
            self.display_message(self.username, message_text, is_sender=True)
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {str(e)}")
            self.connected = False
    
    def display_message(self, sender, message, timestamp=None, is_sender=False, pending=False):
        self.chat_display.config(state='normal')        
        if not timestamp:
            timestamp = datetime.now().strftime('%H:%M:%S')
        prefix = "You: " if is_sender else f"{sender}: "
        if pending:
            prefix = "[Pending] " + prefix
        tag = "sender" if is_sender else "receiver"
        
        self.chat_display.insert(tk.END, f"[{timestamp}] {prefix}{message}\n", tag)
        self.chat_display.tag_config("sender", foreground="blue")
        self.chat_display.tag_config("receiver", foreground="green")       
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)
    
    def display_message_history(self, with_user, messages):
        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)
        for msg in messages:
            is_sender = msg['sender'] == self.username
            pending = not msg['is_read'] and not is_sender
            self.display_message(
                msg['sender'],
                msg['message'],
                msg['timestamp'],
                is_sender=is_sender,
                pending=pending
            )
        
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)
    
    def process_complete_messages(self, buffer):
        messages = buffer.strip().split('\n')
        remaining = ""       
        for i, message in enumerate(messages):
            if message:
                try:
                    data = json.loads(message)
                    self.handle_message(data)
                except json.JSONDecodeError:
                    if i == len(messages) - 1:
                        remaining = message
                    else:
                        print(f"Invalid JSON ignored: {message[:50]}...")
        return remaining
    
    def handle_message(self, data):
        if data['type'] == 'message':
            self.display_message(
                data['sender'],
                data['message'],
                data.get('timestamp'),
                pending=data.get('pending', False)
            )
        elif data['type'] == 'user_list':
            self.update_user_list(data['users'])
        elif data['type'] == 'delivery':
            status = "Delivered" if data['status'] == 'delivered' else "Pending"
            self.chat_display.config(state='normal')
            self.chat_display.insert(tk.END, f"Message to {data['receiver']}: {status}\n", "status")
            self.chat_display.tag_config("status", foreground="gray")
            self.chat_display.config(state='disabled')
            self.chat_display.see(tk.END)
        elif data['type'] == 'message_history':
            self.display_message_history(data['with_user'], data['messages'])
    
    def receive_messages(self):
        while self.connected:
            try:
                chunk = self.client_socket.recv(4096).decode('utf-8')
                if not chunk:
                    print("Server closed connection")
                    self.connected = False
                    break
                self.buffer += chunk
                self.buffer = self.process_complete_messages(self.buffer)    
            except ConnectionResetError:
                print("Server connection reset")
                self.connected = False
            except Exception as e:
                print(f"Error receiving message: {str(e)}")
                self.connected = False
                break
    
    def update_user_list(self, users):
        self.users_listbox.delete(0, tk.END)
        for user in users:
            status = " (online)" if user['online'] else " (offline)"
            self.users_listbox.insert(tk.END, user['username'] + status)
        self.users_listbox.insert(tk.END, "")
        self.users_listbox.insert(tk.END, f"Last updated: {datetime.now().strftime('%H:%M:%S')}")
    
    def on_closing(self):
        self.connected = False
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        if self.receive_thread and self.receive_thread.is_alive():
            self.receive_thread.join(timeout=1)
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()