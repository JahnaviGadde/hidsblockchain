const hre = require("hardhat");

async function main() {
  // Compile the contract
  const Logger = await hre.ethers.getContractFactory("Logger");
  const logger = await Logger.deploy();

  await logger.deployed();
  console.log(`Logger deployed to: ${logger.address}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
