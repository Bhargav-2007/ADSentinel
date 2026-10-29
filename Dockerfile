FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY adsentinel ./adsentinel
RUN pip install --no-cache-dir . && useradd --create-home sentinel && chown -R sentinel:sentinel /app
USER sentinel
ENTRYPOINT ["adsentinel"]
CMD ["--help"]
