const axios = require('axios');
const https = require('https');
const { spawn } = require('child_process');
const fs = require('fs');
const { JsonRpcProvider, Wallet, Contract, keccak256, toUtf8Bytes } = require("ethers");


// Blockchain configuration
const RPC_URL = "http://127.0.0.1:8545"; 
const PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";  
const CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"; 
const ABI = [
  "function storeLogBatch(string memory logHash, uint256 timestamp) public"
];

// ------------------------------
// Elasticsearch configuration
// ------------------------------
const ES_URL = "https://localhost:9200";
const INDEX = "wazuh-alerts*/_search";
const ES_USERNAME = "admin";
const ES_PASSWORD = "SecretPassword";

// ------------------------------
// Wazuh API configuration for pushing alerts
// ------------------------------
const WAZUH_API_BASE_URL = "https://localhost:55000";
const WAZUH_USERNAME = "wazuh-wui";
const WAZUH_PASSWORD = "MyS3cr37P450r.*-" ;


// ------------------------------
// Fetch alerts from Elasticsearch
// ------------------------------
async function fetchAlerts() {
  try {
    const headers = { "Content-Type": "application/json" };
    const query = {
      query: { match_all: {} },
      size: 10
    };

    const agent = new https.Agent({ rejectUnauthorized: false });
    const response = await axios.post(`${ES_URL}/${INDEX}`, query, {
      auth: { username: ES_USERNAME, password: ES_PASSWORD },
      headers,
      httpsAgent: agent
    });
    return response.data.hits.hits;
  } catch (error) {
    console.error("Error fetching alerts from Elasticsearch:", error);
    return [];
  }
}

// ------------------------------
// Run ML model as a child process
// ------------------------------
function runMLModel(alerts, callback) {

  const alertsFile = 'alerts.json';
  fs.writeFileSync(alertsFile, JSON.stringify(alerts));
  
  const mlProcess = spawn('python', ['ml_model.py', alertsFile]);
  
  let mlOutput = "";
  mlProcess.stdout.on('data', (data) => {
    mlOutput += data.toString();
  });
  
  mlProcess.stderr.on('data', (data) => {
    console.error("ML process error:", data.toString());
  });
  
  mlProcess.on('close', (code) => {
    console.log(`ML process exited with code ${code}`);
    callback(mlOutput);
  });
}

async function storeAlertsOnChain(alerts) {
  try {
    // Aggregate the alerts (here, simply converting to JSON and hashing)
    const logsString = JSON.stringify(alerts);
    const logsHash = keccak256(toUtf8Bytes(logsString));
    const timestamp = Math.floor(Date.now() / 1000);

    // Connect to blockchain
    const provider = new JsonRpcProvider(RPC_URL);
    const wallet = new Wallet(PRIVATE_KEY, provider);
    const contract = new Contract(CONTRACT_ADDRESS, ABI, wallet);

    // Call the contract function to store the log batch
    const tx = await contract.storeLogBatch(logsHash, timestamp);
    await tx.wait();
    console.log("Alerts stored on chain. Tx hash:", tx.hash);
  } catch (error) {
    console.error("Error storing alerts on blockchain:", error);
  }
}

// ------------------------------
// Push an alert to Wazuh if an anomaly is detected
// ------------------------------
async function pushAlertToWazuh(alertMessage) {
  try {
    
    const agent = new https.Agent({ rejectUnauthorized: false });

    const authUrl = `${WAZUH_API_BASE_URL}/security/user/authenticate`;
    const authResponse = await axios.post(authUrl, {}, {
      auth: { username: WAZUH_USERNAME, password: WAZUH_PASSWORD },
      headers: { "Content-Type": "application/json" },
      httpsAgent: agent
    });
    const token = authResponse.data.data.token;
    console.log("Obtained Wazuh token:", token);

    const payload = {
      message: alertMessage,

    };
    const headers = {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`
    };
    const alertsUrl = `${WAZUH_API_BASE_URL}/alerts`;
    const response = await axios.post(alertsUrl, payload, { headers, httpsAgent: agent });
    console.log("Alert pushed to Wazuh:", response.data);
  } catch (error) {
    console.error("Error pushing alert to Wazuh:", error);
  }
}

// ------------------------------
// Main process: fetch alerts, run ML model, push alert if needed
// ------------------------------
async function main() {
  const alerts = await fetchAlerts();
  console.log(`Fetched ${alerts.length} alerts.`);
  
  if (alerts.length === 0) {
    console.log("No alerts fetched. Exiting.");
    return;
  }

  await storeAlertsOnChain(alerts); 

  runMLModel(alerts, async (mlOutput) => {
    console.log("ML Model Output:", mlOutput);
    if (mlOutput.includes("ALERT:")) {
      console.log("Anomaly detected. Pushing alert to Wazuh...");
      await pushAlertToWazuh(mlOutput);
    } else {
      console.log("No anomaly detected.");
    }
  });
}

main();
