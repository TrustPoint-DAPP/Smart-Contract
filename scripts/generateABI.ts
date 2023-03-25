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

  const organizationControllerABI =
    OrganizationControllerFactory.interface.format(
      ethers.utils.FormatTypes.json
    );

  const nftABI = NFTFactory.interface.format(ethers.utils.FormatTypes.json);

  const dealControllerABI = DealControllerFactory.interface.format(
    ethers.utils.FormatTypes.json
  );

  const loggerABI = LoggerFactory.interface.format(
    ethers.utils.FormatTypes.json
  );

  saveABIFile(
    "OrganizationController.json",
    organizationControllerABI as string
  );
  saveABIFile("NFT.json", nftABI as string);
  saveABIFile("DealController.json", dealControllerABI as string);
  saveABIFile("Logger.json", loggerABI as string);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
