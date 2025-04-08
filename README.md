# Demo Node mTLS

Companion repo to my blog post on mTLS.

## Getting started

```sh
# Install deps
npm install

# Generate all the required certs
./setup.sh

# Run the server with mTLS configuration
npm run server.ts

# Run the client script to test the mTLS endpoint
npm run client.ts
```
