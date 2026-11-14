#!/bin/bash
VIN="${1:-CV622697F82A936A1}"
curl -s -m 8 -X POST http://10.225.139.2:8080/graphql -H 'Content-Type: application/json' \
  --data-binary "{\"query\":\"query { vehicleDiagnostics(vin:\\\"$VIN\\\") { vin } }\",\"variables\":{\"vin\":\"$VIN\"}}"
