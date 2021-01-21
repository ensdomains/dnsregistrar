const HDWalletProvider = require("@truffle/hdwallet-provider");
require('dotenv').config();

module.exports = {
  networks: {
    ropsten: {
      provider: function() {
        return new HDWalletProvider([process.env.ROPSTEN_KEY], "https://ropsten.infura.io/v3/58a380d3ecd545b2b5b3dad5d2b18bf0");
      },
      network_id: '3',
      from: '0xa303ddc620aa7d1390baccc8a495508b183fab59'
    }
  },
  compilers: {
    solc: {
      version: "0.7.4",
    }
  },
  plugins: [
    'truffle-plugin-verify'
  ],
  api_keys: {
    etherscan: process.env.ETHERSCAN_API_KEY
  }
};
