#!/bin/bash

docker-compose -f docker-compose.prod.yaml --env-file .env.production build
docker-compose -f docker-compose.prod.yaml --env-file .env.production up -d