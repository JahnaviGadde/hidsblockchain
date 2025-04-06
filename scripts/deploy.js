const hre = require("hardhat");

async function main() {
    const LogStorage = await hre.ethers.getContractFactory("LogStorage");
    const logStorage = await LogStorage.deploy();

    await logStorage.waitForDeployment();

    console.log("Contract deployed at:", await logStorage.getAddress());
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
