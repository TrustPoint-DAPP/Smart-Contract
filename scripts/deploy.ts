import { ethers, run } from "hardhat";

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
  await organizationController.deployTransaction.wait(10);
  console.log(
    `The organizaiton controller is deployed to ${organizationController.address}`
  );
  try {
    await run("verify:verify", {
      address: organizationController.address,
      constructorArguments: [],
    });
  } catch (err) {
    console.log(err);
  }

  const dealController = await DealControllerFactory.deploy(
    organizationController.address,
    account,
    oneOffFees,
    royaltyBasisPoints
  );
  await dealController.deployTransaction.wait(10);
  console.log(`The deal controller is deployed to ${dealController.address}`);

  try {
    await run("verify:verify", {
      address: dealController.address,
      constructorArguments: [
        organizationController.address,
        account,
        oneOffFees,
        royaltyBasisPoints,
      ],
    });
  } catch (err) {
    console.log(err);
  }

  const logger = await organizationController.logger();
  console.log(logger);

  await organizationController.grantRole(
    await organizationController.DEAL_MAKER_ROLE(),
    dealController.address
  );

  await dealController.grantRole(
    await dealController.SIGNER_ROLE(),
    "0xC3A877573CC5844D2E9E514e3a187068FefA0cA0"
  );
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
