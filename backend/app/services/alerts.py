import json
from collections import defaultdict
from typing import Any

from fastapi import WebSocket


class AlertBroker:
    def __init__(self):
        self._connections: dict[int, list[WebSocket]] = defaultdict(list)

    async def connect(self, user_id: int, websocket: WebSocket):
        await websocket.accept()
        self._connections[user_id].append(websocket)

    def disconnect(self, user_id: int, websocket: WebSocket):
        if websocket in self._connections[user_id]:
            self._connections[user_id].remove(websocket)

    async def publish(self, user_id: int, payload: dict[str, Any]):
        dead = []
        for socket in self._connections.get(user_id, []):
            try:
                await socket.send_text(json.dumps(payload))
            except Exception:
                dead.append(socket)
        for socket in dead:
            self.disconnect(user_id, socket)


broker = AlertBroker()
