FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY fhem_mcp ./fhem_mcp

# Nicht als root laufen.
RUN useradd --create-home --uid 10001 mcp
USER mcp

EXPOSE 8000

CMD ["python", "-m", "fhem_mcp"]
