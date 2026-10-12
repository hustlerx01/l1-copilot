FROM python:3.12-slim
WORKDIR /app
COPY . .
ENV OLLAMA_HOST=http://ollama:11434 OLLAMA_MODEL=llama3.1:8b
CMD ["python", "-m", "l1copilot.evaluate", "--engine", "auto"]
