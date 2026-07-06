"""
Communication Protocol Module
Defines message types, packet structure, and serialization for client-server communication.
"""

import json
import struct
from dataclasses import dataclass, asdict
from enum import Enum, auto
from typing import Optional, Dict, Any
from datetime import datetime


class MessageType(Enum):
    """Enumeration of all supported message types."""
    CHAT = "chat"           # Regular chat message
    SYSTEM = "system"       # System notification
    JOIN = "join"           # User joined
    LEAVE = "leave"         # User left
    WHISPER = "whisper"     # Private message
    COMMAND = "command"       # Slash command
    HEARTBEAT = "heartbeat" # Keep-alive ping
    ACK = "ack"             # Acknowledgment
    ERROR = "error"         # Error message
    USER_LIST = "user_list" # List of online users
    TYPING = "typing"       # Typing indicator
    FILE_OFFER = "file_offer" # File transfer offer


@dataclass
class Packet:
    """
    Standardized packet structure for all communications.

    Fields:
        msg_type: Type of message (from MessageType)
        sender: Username of sender ("SERVER" for system messages)
        content: Message content or command
        timestamp: ISO format timestamp
        metadata: Additional data (recipient for whispers, command args, etc.)
    """
    msg_type: str
    sender: str
    content: str
    timestamp: str = ""
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        if self.metadata is None:
            self.metadata = {}

    def to_json(self) -> str:
        """Serialize packet to JSON string."""
        return json.dumps(asdict(self), ensure_ascii=False)

    @classmethod
    def from_json(cls, data: str) -> "Packet":
        """Deserialize JSON string to Packet."""
        parsed = json.loads(data)
        return cls(**parsed)

    @classmethod
    def chat(cls, sender: str, content: str) -> "Packet":
        """Create a standard chat message packet."""
        return cls(msg_type=MessageType.CHAT.value, sender=sender, content=content)

    @classmethod
    def system(cls, content: str) -> "Packet":
        """Create a system notification packet."""
        return cls(msg_type=MessageType.SYSTEM.value, sender="SERVER", content=content)

    @classmethod
    def whisper(cls, sender: str, recipient: str, content: str) -> "Packet":
        """Create a private message packet."""
        return cls(
            msg_type=MessageType.WHISPER.value,
            sender=sender,
            content=content,
            metadata={"recipient": recipient}
        )

    @classmethod
    def join(cls, username: str) -> "Packet":
        """Create a user join notification."""
        return cls(msg_type=MessageType.JOIN.value, sender="SERVER",
                   content=f"{username} joined the chat", metadata={"username": username})

    @classmethod
    def leave(cls, username: str) -> "Packet":
        """Create a user leave notification."""
        return cls(msg_type=MessageType.LEAVE.value, sender="SERVER",
                   content=f"{username} left the chat", metadata={"username": username})

    @classmethod
    def user_list(cls, users: list) -> "Packet":
        """Create a user list packet."""
        return cls(
            msg_type=MessageType.USER_LIST.value,
            sender="SERVER",
            content=f"{len(users)} users online",
            metadata={"users": users}
        )

    @classmethod
    def typing(cls, username: str, is_typing: bool = True) -> "Packet":
        """Create a typing indicator packet."""
        return cls(
            msg_type=MessageType.TYPING.value,
            sender=username,
            content="typing..." if is_typing else "",
            metadata={"is_typing": is_typing}
        )

    @classmethod
    def error(cls, content: str) -> "Packet":
        """Create an error packet."""
        return cls(msg_type=MessageType.ERROR.value, sender="SERVER", content=content)


class ProtocolHandler:
    """
    Handles packet framing with length-prefix protocol.
    Ensures complete message delivery over TCP streams.
    """

    HEADER_SIZE = 4  # 4 bytes for message length

    @staticmethod
    def encode_packet(packet: Packet) -> bytes:
        """
        Encode a packet into length-prefixed bytes.
        Format: [4 bytes: length][N bytes: JSON payload]
        """
        payload = packet.to_json().encode("utf-8")
        length = struct.pack("!I", len(payload))  # Network byte order
        return length + payload

    @staticmethod
    def decode_stream(data: bytes) -> tuple:
        """
        Decode packets from a byte stream.
        Returns (list_of_packets, remaining_bytes).
        """
        packets = []
        offset = 0

        while offset + ProtocolHandler.HEADER_SIZE <= len(data):
            length = struct.unpack("!I", data[offset:offset + ProtocolHandler.HEADER_SIZE])[0]

            if offset + ProtocolHandler.HEADER_SIZE + length > len(data):
                break  # Incomplete packet

            payload = data[offset + ProtocolHandler.HEADER_SIZE:offset + ProtocolHandler.HEADER_SIZE + length]
            try:
                packet = Packet.from_json(payload.decode("utf-8"))
                packets.append(packet)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                # Skip corrupted packet
                pass

            offset += ProtocolHandler.HEADER_SIZE + length

        remaining = data[offset:]
        return packets, remaining