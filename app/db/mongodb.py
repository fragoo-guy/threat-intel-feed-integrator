import os
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase


class MongoDBManager:
    client: AsyncIOMotorClient[Any] | None = None
    db: AsyncIOMotorDatabase[Any] | None = None

    @classmethod
    def get_uri(cls) -> str:
        return os.getenv("MONGODB_URI", "mongodb://localhost:27017")

    @classmethod
    def get_db_name(cls) -> str:
        return os.getenv("MONGODB_DB_NAME", "threat_intel")

    @classmethod
    def connect(cls) -> None:
        if cls.client is None:
            uri = cls.get_uri()
            cls.client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=5000)
            cls.db = cls.client[cls.get_db_name()]

    @classmethod
    def disconnect(cls) -> None:
        if cls.client is not None:
            cls.client.close()
            cls.client = None
            cls.db = None

    @classmethod
    def get_database(cls) -> AsyncIOMotorDatabase[Any]:
        if cls.db is None:
            cls.connect()
        assert cls.db is not None
        return cls.db


def get_db() -> AsyncIOMotorDatabase[Any]:
    return MongoDBManager.get_database()
