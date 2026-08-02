#!/bin/sh
set -e

npm run migrate:up
npm run seed-admin

exec node dist/src/index.js
