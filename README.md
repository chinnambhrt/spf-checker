# SPF CHECKER

Spf Checker is a simple tool to validate IP addresses and domains against SPF (Sender Policy Framework) records.

## Features

- Validate IP addresses against SPF records
- Supports various SPF mechanisms and modifiers
- Implements RFC 6652

## RFC 6652

Read more about [RFC 6652](https://datatracker.ietf.org/doc/html/rfc6652).

## Usage

```javascript
const { validateSPF } = require('spf-checker')

validateSPF('35.190.247.16', 'gmail.com').then(resp => {

    const result = resp.result;

    console.log('SPF result', result); // output: SPF result pass

 }).catch(err => {

    done(err);

});

```
