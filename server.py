"""
Secure Chat Server
Multi-threaded TCP server with AES encryption, user management, and admin commands.
"""

import socket
import threading
import time
from collections import deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

from config import HOST, PORT, MAX_CONNECTIONS, BUFFER_SIZE, Colors, MAX_USERNAME_LEN, MAX_MESSAGE_LEN
from crypto_manager import get_crypto_manager
from protocol import Packet, MessageType, ProtocolHandler
from logger import setup_logger


class ClientConnection:
    """Represents a connected client with metadata."""

    def __init__(self, socket: socket.socket, address: tuple, username: str):
        self.socket = socket
        self.address = address
        self.username = username
        self.joined_at = datetime.now()
        self.is_admin = False
        self.is_muted = False
        self.message_count = deque()
        self.buffer = b""
        self.lock = threading.Lock()

    def is_rate_limited(self, max_msgs: int = 10, window: int = 10) -> bool:
        """Check if client has exceeded rate limit."""
        now = datetime.now()
        while self.message_count and self.message_count[0] < now - timedelta(seconds=window):
            self.message_count.popleft()
        return len(self.message_count) >= max_msgs

    def record_message(self):
        """Record a message timestamp for rate limiting."""
        self.message_count.append(datetime.now())

    def send_packet(self, packet: Packet, crypto) -> bool:
        """Send an encrypted packet to this client."""
        try:
            encrypted = crypto.encrypt(packet.to_json())
            enc_packet = Packet(
                msg_type="encrypted",
                sender="SERVER",
                content=encrypted.decode("latin-1")
            )
            framed = ProtocolHandler.encode_packet(enc_packet)
            with self.lock:
                self.socket.sendall(framed)
            return True
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            return False
        except Exception:
            return False


class ChatServer:
    """Main chat server class. Manages connections, message routing, and application state."""

    def __init__(self, host: str = HOST, port: int = PORT):
        self.host = host
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.clients: Dict[str, ClientConnection] = {}
        self.clients_lock = threading.RLock()
        self.banned_ips: Set[str] = set()
        self.admin_password = "admin123"
        self.crypto = get_crypto_manager()
        self.logger = setup_logger("Server")
        self.running = False
        self.start_time = None

    def start(self):
        """Initialize and start the server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(MAX_CONNECTIONS)
        self.running = True
        self.start_time = datetime.now()

        self._print_banner()
        self.logger.info(f"Server started on {self.host}:{self.port}")

        try:
            while self.running:
                try:
                    self.server_socket.settimeout(1.0)
                    client_sock, address = self.server_socket.accept()

                    if address[0] in self.banned_ips:
                        client_sock.close()
                        self.logger.warning(f"Rejected banned IP: {address[0]}")
                        continue

                    thread = threading.Thread(
                        target=self._handle_new_client,
                        args=(client_sock, address),
                        daemon=True
                    )
                    thread.start()

                except socket.timeout:
                    continue
                except OSError:
                    if self.running:
                        raise
                    break
        except KeyboardInterrupt:
            self.logger.info("Shutdown signal received")
        finally:
            self.shutdown()

    def _print_banner(self):
        """Display server startup banner."""
        banner = """
+===========================================================+
|              SECURE CHAT SERVER v1.0.0                    |
+===========================================================+
[*] Listening on {host}:{port}
[!] Press Ctrl+C to stop
""".format(host=self.host, port=self.port)
        print(banner)

    def _handle_new_client(self, client_sock: socket.socket, address: tuple):
        """Handle a new client connection from handshake to main loop."""
        self.logger.info(f"New connection from {address[0]}:{address[1]}")

        try:
            client_sock.settimeout(10.0)

            raw_data = client_sock.recv(BUFFER_SIZE)
            if not raw_data:
                client_sock.close()
                return

            packets, remaining = ProtocolHandler.decode_stream(raw_data)
            if not packets:
                client_sock.close()
                return

            handshake = packets[0]
            username = handshake.content.strip()

            if not self._validate_username(username, client_sock):
                return

            with self.clients_lock:
                if username.lower() in [u.lower() for u in self.clients]:
                    self._send_error(client_sock, "Username already taken. Choose another.")
                    client_sock.close()
                    return

            client = ClientConnection(client_sock, address, username)

            if handshake.metadata.get("admin_password") == self.admin_password:
                client.is_admin = True
                self.logger.info(f"{username} authenticated as admin")

            with self.clients_lock:
                self.clients[username] = client

            welcome = Packet.system(
                f"Welcome to SecureChat, {username}! Type /help for commands."
                + (" [ADMIN]" if client.is_admin else "")
            )
            client.send_packet(welcome, self.crypto)

            self._broadcast(Packet.join(username), exclude=username)
            self._broadcast(Packet.system(f"{username} joined the chat. {len(self.clients)} users online."))

            self._send_user_list(client)

            self.logger.info(f"{username} joined from {address[0]}")

            client_sock.settimeout(None)
            self._client_message_loop(client)

        except socket.timeout:
            self.logger.warning(f"Handshake timeout for {address}")
            client_sock.close()
        except Exception as e:
            self.logger.error(f"Error handling client {address}: {e}")
            client_sock.close()

    def _validate_username(self, username: str, sock: socket.socket) -> bool:
        """Validate username format."""
        if not username or len(username) < 2:
            self._send_error(sock, "Username must be at least 2 characters")
            sock.close()
            return False
        if len(username) > MAX_USERNAME_LEN:
            self._send_error(sock, f"Username too long (max {MAX_USERNAME_LEN})")
            sock.close()
            return False
        if username.startswith("/") or username.lower() == "server":
            self._send_error(sock, "Invalid username")
            sock.close()
            return False
        return True

    def _send_error(self, sock: socket.socket, message: str):
        """Send an error packet to a raw socket."""
        try:
            packet = Packet.error(message)
            framed = ProtocolHandler.encode_packet(packet)
            sock.sendall(framed)
        except:
            pass

    def _client_message_loop(self, client: ClientConnection):
        """Main loop for receiving messages from a client."""
        while self.running:
            try:
                data = client.socket.recv(BUFFER_SIZE)
                if not data:
                    break

                client.buffer += data
                packets, client.buffer = ProtocolHandler.decode_stream(client.buffer)

                for packet in packets:
                    self._process_packet(client, packet)

            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                break
            except Exception as e:
                self.logger.error(f"Error in client loop for {client.username}: {e}")
                break

        self._remove_client(client)

    def _process_packet(self, client: ClientConnection, packet: Packet):
        """Process a received packet from a client."""

        if packet.msg_type == "encrypted":
            try:
                decrypted_json = self.crypto.decrypt(packet.content.encode("latin-1"))
                packet = Packet.from_json(decrypted_json)
            except Exception:
                self.logger.warning(f"Failed to decrypt message from {client.username}")
                return

        if packet.msg_type == MessageType.CHAT.value:
            if client.is_rate_limited():
                client.send_packet(
                    Packet.error("You're sending messages too fast. Slow down!"),
                    self.crypto
                )
                return
            client.record_message()

        if client.is_muted and packet.msg_type == MessageType.CHAT.value:
            client.send_packet(
                Packet.error("You are muted and cannot send messages."),
                self.crypto
            )
            return

        if packet.msg_type == MessageType.CHAT.value:
            self._handle_chat(client, packet)
        elif packet.msg_type == MessageType.WHISPER.value:
            self._handle_whisper(client, packet)
        elif packet.msg_type == MessageType.COMMAND.value:
            self._handle_command(client, packet)
        elif packet.msg_type == MessageType.TYPING.value:
            self._handle_typing(client, packet)
        elif packet.msg_type == MessageType.HEARTBEAT.value:
            client.send_packet(Packet(msg_type=MessageType.ACK.value, sender="SERVER", content="pong"), self.crypto)

    def _handle_chat(self, client: ClientConnection, packet: Packet):
        """Broadcast a chat message to all clients."""
        content = packet.content.strip()
        if not content:
            return
        if len(content) > MAX_MESSAGE_LEN:
            client.send_packet(Packet.error("Message too long"), self.crypto)
            return

        broadcast = Packet.chat(client.username, content)
        self._broadcast(broadcast)

        self.logger.info(f"[{client.username}] {content[:50]}{'...' if len(content) > 50 else ''}")

    def _handle_whisper(self, client: ClientConnection, packet: Packet):
        """Send a private message to a specific user."""
        recipient = packet.metadata.get("recipient", "")
        content = packet.content

        # Case-insensitive lookup
        target = None
        with self.clients_lock:
            for username, conn in self.clients.items():
                if username.lower() == recipient.lower():
                    target = conn
                    break

        if not target:
            client.send_packet(Packet.error(f"User '{recipient}' not found"), self.crypto)
            return

        whisper_packet = Packet.whisper(client.username, target.username, content)
        target.send_packet(whisper_packet, self.crypto)
        client.send_packet(whisper_packet, self.crypto)

        self.logger.info(f"[WHISPER] {client.username} -> {target.username}")

    def _handle_typing(self, client: ClientConnection, packet: Packet):
        """Broadcast typing indicator to other users."""
        typing_packet = Packet.typing(client.username, packet.metadata.get("is_typing", True))
        self._broadcast(typing_packet, exclude=client.username)

    def _handle_command(self, client: ClientConnection, packet: Packet):
        """Process slash commands."""
        parts = packet.content.strip().split()
        if not parts:
            return

        cmd = parts[0].lower()
        args = parts[1:]

        commands = {
            "/help": self._cmd_help,
            "/users": self._cmd_users,
            "/whisper": self._cmd_whisper,
            "/w": self._cmd_whisper,
            "/me": self._cmd_me,
            "/time": self._cmd_time,
            "/uptime": self._cmd_uptime,
            "/admin": self._cmd_admin,
            "/kick": self._cmd_kick,
            "/ban": self._cmd_ban,
            "/mute": self._cmd_mute,
            "/unmute": self._cmd_unmute,
            "/broadcast": self._cmd_broadcast,
            "/clear": self._cmd_clear,
        }

        handler = commands.get(cmd)
        if handler:
            handler(client, args)
        else:
            client.send_packet(Packet.error(f"Unknown command: {cmd}. Type /help for available commands."), self.crypto)

    def _cmd_help(self, client: ClientConnection, args: List[str]):
        """Show help message."""
        help_text = """
AVAILABLE COMMANDS
---------------------------------
General:
  /help              Show this help message
  /users             List online users
  /whisper <user> <msg>  Send private message
  /w <user> <msg>    Alias for /whisper
  /me <action>       Perform an action
  /time              Show server time
  /uptime            Show server uptime
  /clear             Clear your screen

Admin Commands:
  /admin <password>  Authenticate as admin
  /kick <user>       Kick a user
  /ban <user>        Ban a user's IP
  /mute <user>       Mute a user
  /unmute <user>     Unmute a user
  /broadcast <msg>   Send system broadcast
"""
        client.send_packet(Packet.system(help_text), self.crypto)

    def _cmd_users(self, client: ClientConnection, args: List[str]):
        """List online users."""
        with self.clients_lock:
            users = list(self.clients.keys())

        user_list = "\n".join([
            f"  {'[ADMIN] ' if self.clients[u].is_admin else ''}{u}"
            for u in users
        ])
        client.send_packet(Packet.system(f"Online Users ({len(users)}):\n{user_list}"), self.crypto)

    def _cmd_whisper(self, client: ClientConnection, args: List[str]):
        """Handle whisper command."""
        if len(args) < 2:
            client.send_packet(Packet.error("Usage: /whisper <username> <message>"), self.crypto)
            return

        target_name = args[0]
        message = " ".join(args[1:])

        # Case-insensitive lookup
        target = None
        with self.clients_lock:
            for username, conn in self.clients.items():
                if username.lower() == target_name.lower():
                    target = conn
                    break

        if not target:
            client.send_packet(Packet.error(f"User '{target_name}' not found"), self.crypto)
            return

        whisper = Packet.whisper(client.username, target.username, message)
        target.send_packet(whisper, self.crypto)
        client.send_packet(whisper, self.crypto)

    def _cmd_me(self, client: ClientConnection, args: List[str]):
        """Perform an action."""
        action = " ".join(args)
        self._broadcast(Packet.system(f"* {client.username} {action}"))

    def _cmd_time(self, client: ClientConnection, args: List[str]):
        """Show server time."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client.send_packet(Packet.system(f"Server time: {now}"), self.crypto)

    def _cmd_uptime(self, client: ClientConnection, args: List[str]):
        """Show server uptime."""
        uptime = datetime.now() - self.start_time
        hours, remainder = divmod(int(uptime.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        client.send_packet(
            Packet.system(f"Uptime: {hours}h {minutes}m {seconds}s"),
            self.crypto
        )

    def _cmd_admin(self, client: ClientConnection, args: List[str]):
        """Authenticate as admin."""
        if not args:
            client.send_packet(Packet.error("Usage: /admin <password>"), self.crypto)
            return

        if args[0] == self.admin_password:
            client.is_admin = True
            client.send_packet(Packet.system("You are now an admin!"), self.crypto)
            self.logger.info(f"{client.username} promoted to admin")
        else:
            client.send_packet(Packet.error("Invalid admin password"), self.crypto)

    def _cmd_kick(self, client: ClientConnection, args: List[str]):
        """Kick a user (admin only)."""
        if not self._require_admin(client):
            return
        if not args:
            client.send_packet(Packet.error("Usage: /kick <username>"), self.crypto)
            return

        target_name = args[0]

        # Case-insensitive lookup
        target = None
        with self.clients_lock:
            for username, conn in self.clients.items():
                if username.lower() == target_name.lower():
                    target = conn
                    break

        if not target:
            client.send_packet(Packet.error(f"User '{target_name}' not found"), self.crypto)
            return

        reason = " ".join(args[1:]) if len(args) > 1 else "Kicked by admin"
        target.send_packet(Packet.system(f"You have been kicked: {reason}"), self.crypto)
        self._broadcast(Packet.system(f"{target.username} was kicked by {client.username}"))
        self._remove_client(target)
        self.logger.info(f"{target.username} kicked by {client.username}: {reason}")

    def _cmd_ban(self, client: ClientConnection, args: List[str]):
        """Ban a user's IP (admin only)."""
        if not self._require_admin(client):
            return
        if not args:
            client.send_packet(Packet.error("Usage: /ban <username>"), self.crypto)
            return

        target_name = args[0]

        # Case-insensitive lookup
        target = None
        with self.clients_lock:
            for username, conn in self.clients.items():
                if username.lower() == target_name.lower():
                    target = conn
                    break

        if not target:
            client.send_packet(Packet.error(f"User '{target_name}' not found"), self.crypto)
            return

        self.banned_ips.add(target.address[0])
        target.send_packet(Packet.system("You have been banned from this server"), self.crypto)
        self._broadcast(Packet.system(f"{target.username} was banned by {client.username}"))
        self._remove_client(target)
        self.logger.warning(f"{target.username} ({target.address[0]}) banned by {client.username}")

    def _cmd_mute(self, client: ClientConnection, args: List[str]):
        """Mute a user (admin only)."""
        if not self._require_admin(client):
            return
        if not args:
            client.send_packet(Packet.error("Usage: /mute <username>"), self.crypto)
            return

        target_name = args[0]

        # Case-insensitive lookup
        target = None
        with self.clients_lock:
            for username, conn in self.clients.items():
                if username.lower() == target_name.lower():
                    target = conn
                    break

        if not target:
            client.send_packet(Packet.error(f"User '{target_name}' not found"), self.crypto)
            return

        target.is_muted = True
        target.send_packet(Packet.system("You have been muted"), self.crypto)
        self._broadcast(Packet.system(f"{target.username} was muted by {client.username}"))
        self.logger.info(f"{target.username} muted by {client.username}")

    def _cmd_unmute(self, client: ClientConnection, args: List[str]):
        """Unmute a user (admin only)."""
        if not self._require_admin(client):
            return
        if not args:
            client.send_packet(Packet.error("Usage: /unmute <username>"), self.crypto)
            return

        target_name = args[0]

        # Case-insensitive lookup
        target = None
        with self.clients_lock:
            for username, conn in self.clients.items():
                if username.lower() == target_name.lower():
                    target = conn
                    break

        if not target:
            client.send_packet(Packet.error(f"User '{target_name}' not found"), self.crypto)
            return

        target.is_muted = False
        target.send_packet(Packet.system("You have been unmuted"), self.crypto)
        self._broadcast(Packet.system(f"{target.username} was unmuted by {client.username}"))
        self.logger.info(f"{target.username} unmuted by {client.username}")

    def _cmd_broadcast(self, client: ClientConnection, args: List[str]):
        """Broadcast a system message (admin only)."""
        if not self._require_admin(client):
            return
        if not args:
            client.send_packet(Packet.error("Usage: /broadcast <message>"), self.crypto)
            return

        message = " ".join(args)
        self._broadcast(Packet.system(f"[BROADCAST] {message}"))
        self.logger.info(f"Broadcast by {client.username}: {message}")

    def _cmd_clear(self, client: ClientConnection, args: List[str]):
        """Send clear screen command to client."""
        client.send_packet(
            Packet(msg_type=MessageType.COMMAND.value, sender="SERVER",
                   content="/clear", metadata={"action": "clear"}),
            self.crypto
        )

    def _require_admin(self, client: ClientConnection) -> bool:
        """Check if client has admin privileges."""
        if not client.is_admin:
            client.send_packet(Packet.error("Admin privileges required"), self.crypto)
            return False
        return True

    def _broadcast(self, packet: Packet, exclude: str = None):
        """Send a packet to all connected clients."""
        with self.clients_lock:
            clients_copy = list(self.clients.values())

        for client in clients_copy:
            if exclude and client.username == exclude:
                continue
            client.send_packet(packet, self.crypto)

    def _send_user_list(self, client: ClientConnection):
        """Send the list of online users to a client."""
        with self.clients_lock:
            users = list(self.clients.keys())
        client.send_packet(Packet.user_list(users), self.crypto)

    def _remove_client(self, client: ClientConnection):
        """Clean up a disconnected client."""
        with self.clients_lock:
            if client.username in self.clients:
                del self.clients[client.username]

        try:
            client.socket.close()
        except:
            pass

        self._broadcast(Packet.leave(client.username))
        self._broadcast(Packet.system(f"{client.username} left the chat. {len(self.clients)} users online."))
        self.logger.info(f"{client.username} disconnected")

    def shutdown(self):
        """Gracefully shut down the server."""
        self.running = False
        self.logger.info("Shutting down server...")

        self._broadcast(Packet.system("Server is shutting down. Goodbye!"))

        with self.clients_lock:
            for client in list(self.clients.values()):
                try:
                    client.socket.close()
                except:
                    pass
            self.clients.clear()

        if self.server_socket:
            self.server_socket.close()

        self.logger.info("Server stopped")
        print("\nServer stopped.")

    def _find_client(self, name: str) -> Optional[ClientConnection]:
        """Find a client by username (case-insensitive)."""
        with self.clients_lock:
            for username, conn in self.clients.items():
                if username.lower() == name.lower():
                    return conn
        return None


def main():
    """Entry point for the server."""
    server = ChatServer()
    server.start()


if __name__ == "__main__":
    main()