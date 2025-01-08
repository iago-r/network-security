#!/bin/bash
set -eu

docker volume rm --force pgdata
docker compose --project-name sgis up --detach
sleep 10s
docker cp sgis_schema.sql sgis-psql-1:/root.sql
docker compose -p sgis exec psql psql -U postgres --file /root.sql
# docker cp sgis_mock_data.sql sgis-psql-1:/data.sql
# docker compose -p sgis exec psql psql -U postgres --file /data.sql
