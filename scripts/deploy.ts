import { ethers } from "hardhat";

const royaltyBasisPoints = 50;
const oneOffFees = 100;

async function main() {
  const signers = await ethers.getSigners();
  const account = await signers[0].getAddress();

  const OrganizationControllerFactory = await ethers.getContractFactory(
    "OrganizationController"
  );
  const DealControllerFactory = await ethers.getContractFactory(
    "DealController"
  );

  const organizationController = await OrganizationControllerFactory.deploy();
  await organizationController.deployed();
  console.log(
    `The organizaiton controller is deployed to ${organizationController.address}`
  );

  const dealController = await DealControllerFactory.deploy(
    organizationController.address,
    account,
    oneOffFees,
    royaltyBasisPoints
  );
  await dealController.deployed();
  console.log(`The deal controller is deployed to ${dealController.address}`);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
