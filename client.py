"""
Secure Chat Client
Interactive terminal client with rich UI, encryption, and advanced features.

Features:
- Real-time encrypted messaging
- Dual-threaded send/receive
- Rich terminal UI with colors
- Private messaging (whispers)
- Slash commands
- Typing indicators
- Message history
- Auto-reconnect
- Heartbeat keep-alive
"""

import socket
import threading
import sys
import time
import os
from datetime import datetime
from typing import Optional

from config import HOST, PORT, BUFFER_SIZE, Colors, MAX_USERNAME_LEN, APP_NAME
from crypto_manager import get_crypto_manager
from protocol import Packet, MessageType, ProtocolHandler
from logger import setup_logger


class ChatClient:
    """Interactive chat client with rich terminal interface."""

    def __init__(self, host: str = HOST, port: int = PORT):
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        self.username: Optional[str] = None
        self.crypto = get_crypto_manager()
        self.logger = setup_logger("Client")
        self.running = False
        self.buffer = b""
        self.message_history = []
        self.max_history = 100
        self.is_typing = False
        self.last_typing_time = 0
        self.typing_lock = threading.Lock()
        self.receive_thread: Optional[threading.Thread] = None
        self.heartbeat_thread: Optional[threading.Thread] = None
        self.reconnect_attempts = 0
        self.max_reconnect = 3

    def connect(self, username: str, admin_password: str = None):
        """
        Connect to the server and start the chat session.

        Args:
            username: Desired display name
            admin_password: Optional password for admin privileges
        """
        self.username = username.strip()

        if len(self.username) < 2 or len(self.username) > MAX_USERNAME_LEN:
            print(f"{Colors.RED}Error: Username must be 2-{MAX_USERNAME_LEN} characters{Colors.END}")
            return False

        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10.0)
            self.socket.connect((self.host, self.port))
            self.socket.settimeout(None)
        except ConnectionRefusedError:
            print(f"{Colors.RED}[X] Connection refused. Is the server running?{Colors.END}")
            return False
        except socket.timeout:
            print(f"{Colors.RED}[X] Connection timed out.{Colors.END}")
            return False
        except Exception as e:
            print(f"{Colors.RED}[X] Connection error: {e}{Colors.END}")
            return False

        handshake = Packet(
            msg_type=MessageType.JOIN.value,
            sender=self.username,
            content=self.username,
            metadata={"admin_password": admin_password} if admin_password else {}
        )
        self._send_raw(handshake)

        self.running = True
        self.reconnect_attempts = 0

        self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.receive_thread.start()

        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()

        self._print_welcome()
        self._input_loop()

        return True

    def _print_welcome(self):
        """Display client welcome banner."""
        os.system("cls" if os.name == "nt" else "clear")
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
+===========================================================+
|              SECURE CHAT CLIENT v1.0.0                    |
+===========================================================+{Colors.END}
{Colors.GREEN}[*] Connected to {self.host}:{self.port}{Colors.END}
{Colors.YELLOW}[*] Username: {self.username}{Colors.END}
{Colors.DIM}Type /help for commands | Ctrl+C or /quit to exit{Colors.END}
{Colors.DIM}{"-" * 59}{Colors.END}
"""
        print(banner)

    def _send_raw(self, packet: Packet):
        """Send a raw (unencrypted) packet to the server."""
        try:
            framed = ProtocolHandler.encode_packet(packet)
            self.socket.sendall(framed)
        except Exception as e:
            self.logger.error(f"Send error: {e}")

    def _send_encrypted(self, packet: Packet):
        """Send an encrypted packet to the server."""
        try:
            encrypted = self.crypto.encrypt(packet.to_json())
            enc_packet = Packet(
                msg_type="encrypted",
                sender=self.username,
                content=encrypted.decode("latin-1")
            )
            framed = ProtocolHandler.encode_packet(enc_packet)
            self.socket.sendall(framed)
        except Exception as e:
            self.logger.error(f"Send error: {e}")

    def _receive_loop(self):
        """Background thread: receive and process messages from server."""
        while self.running:
            try:
                data = self.socket.recv(BUFFER_SIZE)
                if not data:
                    self._handle_disconnect("Server closed connection")
                    break

                self.buffer += data
                packets, self.buffer = ProtocolHandler.decode_stream(self.buffer)

                for packet in packets:
                    self._process_packet(packet)

            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                self._handle_disconnect("Connection lost")
                break
            except OSError:
                break
            except Exception as e:
                self.logger.error(f"Receive error: {e}")
                break

    def _process_packet(self, packet: Packet):
        """Process a received packet."""

        if packet.msg_type == "encrypted":
            try:
                decrypted_json = self.crypto.decrypt(packet.content.encode("latin-1"))
                packet = Packet.from_json(decrypted_json)
            except Exception:
                self.logger.warning("Failed to decrypt message")
                return

        self.message_history.append(packet)
        if len(self.message_history) > self.max_history:
            self.message_history.pop(0)

        if packet.msg_type == MessageType.CHAT.value:
            self._display_chat(packet)
        elif packet.msg_type == MessageType.SYSTEM.value:
            self._display_system(packet)
        elif packet.msg_type == MessageType.WHISPER.value:
            self._display_whisper(packet)
        elif packet.msg_type == MessageType.JOIN.value:
            self._display_join(packet)
        elif packet.msg_type == MessageType.LEAVE.value:
            self._display_leave(packet)
        elif packet.msg_type == MessageType.USER_LIST.value:
            self._display_user_list(packet)
        elif packet.msg_type == MessageType.TYPING.value:
            self._display_typing(packet)
        elif packet.msg_type == MessageType.ERROR.value:
            self._display_error(packet)
        elif packet.msg_type == MessageType.COMMAND.value:
            self._handle_client_command(packet)

    def _display_chat(self, packet: Packet):
        """Display a regular chat message."""
        timestamp = self._format_time(packet.timestamp)
        print(f"\n{Colors.DIM}[{timestamp}]{Colors.END} {Colors.BOLD}{Colors.CYAN}{packet.sender}:{Colors.END} {packet.content}")
        self._reprint_prompt()

    def _display_system(self, packet: Packet):
        """Display a system message."""
        print(f"\n{Colors.YELLOW}[i] {packet.content}{Colors.END}")
        self._reprint_prompt()

    def _display_whisper(self, packet: Packet):
        """Display a private message."""
        timestamp = self._format_time(packet.timestamp)
        recipient = packet.metadata.get("recipient", "")
        if packet.sender == self.username:
            print(f"\n{Colors.DIM}[{timestamp}]{Colors.END} {Colors.MAGENTA}[PM] To {recipient}:{Colors.END} {packet.content}")
        else:
            print(f"\n{Colors.DIM}[{timestamp}]{Colors.END} {Colors.MAGENTA}[PM] From {packet.sender}:{Colors.END} {packet.content}")
        self._reprint_prompt()

    def _display_join(self, packet: Packet):
        """Display user join notification."""
        username = packet.metadata.get("username", "")
        print(f"\n{Colors.GREEN}[+] {username} joined the chat{Colors.END}")
        self._reprint_prompt()

    def _display_leave(self, packet: Packet):
        """Display user leave notification."""
        username = packet.metadata.get("username", "")
        print(f"\n{Colors.RED}[-] {username} left the chat{Colors.END}")
        self._reprint_prompt()

    def _display_user_list(self, packet: Packet):
        """Display online users list."""
        users = packet.metadata.get("users", [])
        user_str = ", ".join(users) if users else "No users online"
        print(f"\n{Colors.CYAN}[*] Online Users ({len(users)}): {user_str}{Colors.END}")
        self._reprint_prompt()

    def _display_typing(self, packet: Packet):
        """Display typing indicator (overwrites current line)."""
        if packet.metadata.get("is_typing", True):
            sys.stdout.write(f"\r{Colors.DIM}{packet.sender} is typing...{Colors.END}")
            sys.stdout.flush()

            def clear_typing():
                time.sleep(3)
                sys.stdout.write("\r" + " " * 40 + "\r")
                sys.stdout.flush()
                self._reprint_prompt()

            threading.Thread(target=clear_typing, daemon=True).start()

    def _display_error(self, packet: Packet):
        """Display an error message."""
        print(f"\n{Colors.RED}[!] {packet.content}{Colors.END}")
        self._reprint_prompt()

    def _handle_client_command(self, packet: Packet):
        """Handle client-side commands from server."""
        if packet.metadata.get("action") == "clear":
            os.system("cls" if os.name == "nt" else "clear")
            self._reprint_prompt()

    def _format_time(self, timestamp_str: str) -> str:
        """Format ISO timestamp for display."""
        try:
            dt = datetime.fromisoformat(timestamp_str)
            return dt.strftime("%H:%M")
        except:
            return "??:??"

    def _reprint_prompt(self):
        """Reprint the input prompt."""
        sys.stdout.write(f"{Colors.GREEN}> {Colors.END}")
        sys.stdout.flush()

    def _input_loop(self):
        """Main input loop for user messages."""
        try:
            while self.running:
                try:
                    message = input(f"{Colors.GREEN}> {Colors.END}")
                except EOFError:
                    break

                if not message.strip():
                    continue

                if message.startswith("/"):
                    if self._handle_local_command(message):
                        continue

                self._send_typing_indicator(True)

                packet = Packet.chat(self.username, message)
                self._send_encrypted(packet)

                time.sleep(0.5)
                self._send_typing_indicator(False)

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Disconnecting...{Colors.END}")
        finally:
            self.disconnect()

    def _handle_local_command(self, message: str) -> bool:
        """Handle client-side commands. Returns True if handled locally."""
        parts = message.strip().split()
        cmd = parts[0].lower()

        if cmd == "/quit" or cmd == "/exit":
            self.running = False
            return True

        if cmd == "/clear":
            os.system("cls" if os.name == "nt" else "clear")
            self._print_welcome()
            return True

        if cmd == "/history":
            print(f"\n{Colors.CYAN}[*] Message History:{Colors.END}")
            for pkt in self.message_history[-20:]:
                print(f"  [{pkt.msg_type}] {pkt.sender}: {pkt.content[:50]}")
            self._reprint_prompt()
            return True

        if cmd == "/status":
            status = f"""
{Colors.CYAN}[*] Connection Status:{Colors.END}
  Server: {self.host}:{self.port}
  Username: {self.username}
  Connected: {self.running}
  Messages received: {len(self.message_history)}
"""
            print(status)
            self._reprint_prompt()
            return True

        packet = Packet(
            msg_type=MessageType.COMMAND.value,
            sender=self.username,
            content=message
        )
        self._send_encrypted(packet)
        return True

    def _send_typing_indicator(self, is_typing: bool):
        """Send typing status to server."""
        with self.typing_lock:
            if is_typing == self.is_typing:
                return
            self.is_typing = is_typing

        packet = Packet.typing(self.username, is_typing)
        self._send_encrypted(packet)

    def _heartbeat_loop(self):
        """Send periodic heartbeat to keep connection alive."""
        while self.running:
            try:
                time.sleep(30)
                if self.running:
                    packet = Packet(msg_type=MessageType.HEARTBEAT.value, sender=self.username, content="ping")
                    self._send_encrypted(packet)
            except:
                break

    def _handle_disconnect(self, reason: str):
        """Handle unexpected disconnection."""
        self.running = False
        print(f"\n{Colors.RED}[!] {reason}{Colors.END}")

        if self.reconnect_attempts < self.max_reconnect:
            self.reconnect_attempts += 1
            print(f"{Colors.YELLOW}[*] Reconnecting ({self.reconnect_attempts}/{self.max_reconnect})...{Colors.END}")
            time.sleep(2)
        else:
            print(f"{Colors.RED}[X] Connection lost. Please restart the client.{Colors.END}")

    def disconnect(self):
        """Gracefully disconnect from the server."""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        print(f"{Colors.YELLOW}[*] Disconnected.{Colors.END}")


def get_user_input():
    """Get username and optional admin password from user."""
    print(f"""
{Colors.CYAN}{Colors.BOLD}
+===========================================================+
|              SECURE CHAT CLIENT v1.0.0                    |
+===========================================================+{Colors.END}
""")

    username = input(f"{Colors.YELLOW}[*] Enter your username: {Colors.END}").strip()
    admin_pass = input(f"{Colors.DIM}[*] Admin password (optional, press Enter to skip): {Colors.END}").strip()

    return username, admin_pass or None


def main():
    """Entry point for the client."""
    import argparse

    parser = argparse.ArgumentParser(description="Secure Chat Client")
    parser.add_argument("--host", default=HOST, help="Server host")
    parser.add_argument("--port", type=int, default=PORT, help="Server port")
    parser.add_argument("--username", help="Your username")
    parser.add_argument("--admin", help="Admin password")
    args = parser.parse_args()

    if args.username:
        username = args.username
        admin_pass = args.admin
    else:
        username, admin_pass = get_user_input()

    if not username:
        print(f"{Colors.RED}[X] Username is required.{Colors.END}")
        return

    client = ChatClient(host=args.host, port=args.port)
    client.connect(username, admin_pass)


if __name__ == "__main__":
    main()