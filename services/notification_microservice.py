import httpx

from config.config import get_settings

settings = get_settings()


class Notification:
    code_sender_url = settings.NOTIFICATION_CODE_SENDER

    async def code_call(self, payload: dict, request):
        headers = {"unique_id": request.state.unique_id}
        async with httpx.AsyncClient(headers=headers) as client:
            response = await client.post(self.code_sender_url, json=payload)
        # response.raise_for_status()
        return response


notification_client = Notification()


def get_notification_client():
    return notification_client
