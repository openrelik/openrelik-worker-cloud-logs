# OpenRelik worker for Cloud Logs

## Description

This worker processes Cloud logs and make them Timesketch compatible.

## Deploy

Add the below configuration to the OpenRelik `docker-compose.yml` file.

```yaml
openrelik-worker-cloud-logs:
    container_name: openrelik-worker-cloud-logs
    image: ghcr.io/openrelik/openrelik-worker-cloud-logs:latest
    restart: always
    environment:
      - REDIS_URL=redis://openrelik-redis:6379
      - OPENRELIK_PYDEBUG=0
    volumes:
      - ./data:/usr/share/openrelik/data
    command: "celery --app=src.app worker --task-events --concurrency=4 --loglevel=INFO -Q openrelik-worker-cloud-logs"
    # ports:
      # - 5678:5678 # For debugging purposes.
```

## Test

Run the following command.

```
pip install poetry
poetry install --with test --no-root
poetry run pytest --cov=. -v
```
