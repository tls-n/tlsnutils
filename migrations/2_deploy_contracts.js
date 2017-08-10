var tlsnutils = artifacts.require("./tlsnutils.sol");
var ECMath = artifacts.require("./ECMath.sol");
var bytesutils = artifacts.require("./imported/bytesutils.sol");

module.exports = function(deployer) {
  deployer.deploy(bytesutils);
  deployer.link(bytesutils, tlsnutils);
  deployer.deploy(ECMath);
  deployer.link(ECMath, tlsnutils);
  deployer.deploy(tlsnutils);
};
