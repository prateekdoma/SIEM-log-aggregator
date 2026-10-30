# Built from the repo root (context: .) so the image can include common/.
FROM python:3.12-slim

WORKDIR /app
COPY intel/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common/ ./common/
COPY intel/ ./intel/

ENTRYPOINT ["python", "-u", "-m", "intel.updater"]
