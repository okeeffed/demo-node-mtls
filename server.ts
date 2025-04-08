// server.ts
import https from "node:https";
import fs from "node:fs";
import type { TLSSocket } from "node:tls";

try {
  // Read the files
  const serverKey = fs.readFileSync("certs/server.key");
  const serverCert = fs.readFileSync("certs/server-chain.crt"); // Using individual cert
  const caCert = fs.readFileSync("certs/rootCA.crt"); // Using full CA chain

  function isTlsSocket(socket: unknown): socket is TLSSocket {
    return !!socket && typeof socket === "object" && "authorized" in socket;
  }

  const server = https.createServer(
    {
      key: serverKey,
      cert: serverCert,
      ca: caCert,
      requestCert: true,
      rejectUnauthorized: true,
    },
    (req, res) => {
      const tlsSocket = req.socket;

      if (!isTlsSocket(tlsSocket)) {
        console.error("Invalid socket properties");
        res.writeHead(500);
        res.end("Server error");
        return;
      }

      console.log("TLS Connection Details:");
      console.log(`- Authorized: ${tlsSocket.authorized}`);
      console.log(`- Protocol: ${tlsSocket.getProtocol()}`);
      console.log(`- Cipher: ${tlsSocket.getCipher().name}`);

      if (tlsSocket.getPeerCertificate) {
        const cert = tlsSocket.getPeerCertificate(true);
        console.log(`- Client Subject: ${cert.subject?.CN || "Unknown"}`);
        console.log(`- Client Issuer: ${cert.issuer?.CN || "Unknown"}`);
      }

      if (!tlsSocket.authorized) {
        console.error(`Auth Error: ${tlsSocket.authorizationError}`);
        res.writeHead(401);
        res.end(
          `Client certificate not authorized: ${tlsSocket.authorizationError}`,
        );
        return;
      }

      res.writeHead(200);
      res.end("Hello, secure world with intermediate CA!");
    },
  );

  server.on("tlsClientError", (err) => {
    console.error("TLS Client Error:", err);
  });

  server.listen(3000, () => {
    console.log("✅ HTTPS server running at https://localhost:3000");
  });
} catch (err) {
  console.error("Failed to start server:", err);
}
