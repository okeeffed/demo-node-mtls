// client.ts
import https from "node:https";
import fs from "node:fs";
import axios from "axios";

// Read the files with better error handling
try {
  const clientKey = fs.readFileSync("certs/client.key");
  const clientCert = fs.readFileSync("certs/client.crt"); // Using individual cert, not chain
  const caCert = fs.readFileSync("certs/ca-chain.crt"); // Using full CA chain

  const agent = new https.Agent({
    key: clientKey,
    cert: clientCert,
    ca: caCert,
    rejectUnauthorized: true,
  });

  console.log("Starting mTLS client request...");

  axios
    .get("https://localhost:3000", {
      httpsAgent: agent,
      timeout: 10000, // Longer timeout for debugging
    })
    .then((res) => {
      console.log("✅ Server response status:", res.status);
      console.log("✅ Server response data:", res.data);
    })
    .catch((err) => {
      console.error("❌ Request failed:");
      if (err.response) {
        console.error(`Status: ${err.response.status}`);
        console.error(`Response: ${JSON.stringify(err.response.data)}`);
      } else if (err.request) {
        console.error("No response received from server");
      } else {
        console.error(`Error: ${err.message}`);
      }

      if (err.code) {
        console.error(`Error code: ${err.code}`);
      }

      // More detailed error info for TLS issues
      if (err.cause) {
        console.error("Error cause:", err.cause);
      }
    });
} catch (err) {
  console.error("Failed to read certificate files:", err);
}
