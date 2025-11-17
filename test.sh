#!/bin/bash

curl -X POST http://localhost:8083/sign \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:example:document">
    <soapenv:Header>
        <urn:MessageID>MSG123456789</urn:MessageID>
        <urn:CreationDateTime>2025-11-17T16:43:00Z</urn:CreationDateTime>
    </soapenv:Header>
    <soapenv:Body>
        <urn:Transaction>
            <urn:TransactionID>TXN987654321</urn:TransactionID>
            <urn:Amount currency="USD">1000.00</urn:Amount>
            <urn:Description>Example transaction</urn:Description>
        </urn:Transaction>
    </soapenv:Body>
</soapenv:Envelope>'