import json

import httpx


class Notification:
    code_sender_url = "http://127.0.0.1:8002/notification/v1/code_sender"

    async def code_call(self, payload: dict):
        async with httpx.AsyncClient() as client:
            response = await client.post(self.code_sender_url, json=payload)
        # response.raise_for_status()
        return response


notification_client = Notification()


def get_notification_client():
    return notification_client
