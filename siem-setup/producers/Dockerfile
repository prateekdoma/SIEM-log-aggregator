# Built from the repo root (context: .) so the image can include common/.
FROM python:3.12-slim

WORKDIR /app
COPY producers/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common/ ./common/
COPY producers/ ./producers/

ENTRYPOINT ["python", "-u", "-m", "producers.tail"]
