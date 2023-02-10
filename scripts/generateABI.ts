import { ethers } from "hardhat";
import fs from "fs";

function saveABIFile(fileName: string, content: string, dirPath = "./abi") {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath);
  }

  const filePath = `${dirPath}/${fileName}`;

  if (fs.existsSync(filePath)) {
    fs.rmSync(filePath);
  }

  fs.writeFileSync(filePath, content);
}

async function main() {
  const OrganizationControllerFactory = await ethers.getContractFactory(
    "OrganizationController"
  );
  const NFTFactory = await ethers.getContractFactory("NFT");
  const DealControllerFactory = await ethers.getContractFactory(
    "DealController"
  );
  const LoggerFactory = await ethers.getContractFactory("Logger");
  const organizationControllerABI = JSON.stringify(
    OrganizationControllerFactory.interface.format()
  );

  const nftABI = JSON.stringify(NFTFactory.interface.format());

  const dealControllerABI = JSON.stringify(
    DealControllerFactory.interface.format()
  );

  const loggerABI = JSON.stringify(LoggerFactory.interface.format());
  saveABIFile("OrganizationController.json", organizationControllerABI);
  saveABIFile("NFT.json", nftABI);
  saveABIFile("DealController.json", dealControllerABI);
  saveABIFile("Logger.json", loggerABI);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
