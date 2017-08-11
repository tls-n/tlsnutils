# TLS-N Utility Library
## Overview
This library allows the verification and parsing of [TLS-N](https://tls-n.org) proofs. 
This version supports proofs with chunk-level granularity signed by a TLS certificate using secp256r1.
The TLS-N Utility Library makes use of [solidity-bytesutils](https://github.com/tls-n/solidity-bytesutils) to parse the proofs.

## Examples
### Verifying a proof

```
	bytes memory proof = '\x20\x00\x10....
	bool res = tlsnutils.verifyProof(proof);
```

### Getting the generator's response
```
    bytes memory proof = '\x20\x00\x10....
	bytes memory response = tlsnutils.getResponse(proof);
```

### Getting the requested URL in case of HTTP
```
    bytes memory proof = '\x20\x00\x10....
	bytes memory url = tlsnutils.getHTTPRequestURL(proof);
```

### Getting the generator's HTTP body (the HTTP response) in case of HTTP
```
    bytes memory proof = '\x20\x00\x10....
    bytes memory body = tlsnutils.getHTTPBody(proof);
```

## Full Example
For a full example of the library in action, please see [BTCPriceFeed](https://github.com/tls-n/BTCPriceFeed).

## Ropsten Deployment
The tlsnutils library is deployed on Ropsten (Ethereum's test network) at address [0x92522f31816307715736bf49062f6edd80187bbf](https://ropsten.io/address/0x92522f31816307715736bf49062f6edd80187bbf).
