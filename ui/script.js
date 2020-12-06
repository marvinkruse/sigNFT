"use strict";

/**
 * Example JavaScript code that interacts with the page and Web3 wallets
 */

let jsonABI = JSON.parse(`[{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"inputs":[{"internalType":"address","name":"_tokenContractAddress","type":"address"},{"internalType":"address[]","name":"_contractDelegates","type":"address[]"},{"internalType":"bool","name":"_whitelistAsDefault","type":"bool"}],"name":"activateTokenContract","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_tokenContractAddress","type":"address"},{"internalType":"uint256","name":"_tokenID","type":"uint256"}],"name":"activateWhitelist","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_tokenContractAddress","type":"address"},{"internalType":"address[]","name":"_contractDelegates","type":"address[]"}],"name":"addContractDelegates","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_tokenContractAddress","type":"address"},{"internalType":"uint256","name":"_tokenID","type":"uint256"},{"internalType":"address[]","name":"_whitelistedSigners","type":"address[]"}],"name":"addToWhiteList","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_tokenContractAddress","type":"address"},{"internalType":"uint256[]","name":"_tokenIDs","type":"uint256[]"},{"internalType":"address[]","name":"_tokenDelegates","type":"address[]"}],"name":"addTokenDelegate","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_tokenContractAddress","type":"address"},{"internalType":"bool","name":"_whitelistAsDefault","type":"bool"}],"name":"changeWhitelistDefault","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_tokenContractAddress","type":"address"},{"internalType":"uint256","name":"_tokenID","type":"uint256"}],"name":"deactivateWhitelist","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_tokenContractAddress","type":"address"},{"internalType":"uint256","name":"_tokenID","type":"uint256"}],"name":"getSignatures","outputs":[{"internalType":"address[]","name":"signersOfToken","type":"address[]"},{"internalType":"bytes[]","name":"signaturesOfToken","type":"bytes[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_tokenContractAddress","type":"address"},{"internalType":"uint256","name":"_tokenID","type":"uint256"}],"name":"getSigners","outputs":[{"internalType":"address[]","name":"signersOfToken","type":"address[]"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_tokenContractAddress","type":"address"},{"internalType":"address[]","name":"_contractDelegates","type":"address[]"}],"name":"removeContractDelegates","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_tokenContractAddress","type":"address"},{"internalType":"uint256","name":"_tokenID","type":"uint256"},{"internalType":"address[]","name":"_whitelistedSigners","type":"address[]"}],"name":"removeFromWhitelist","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_tokenContractAddress","type":"address"},{"internalType":"uint256[]","name":"_tokenIDs","type":"uint256[]"},{"internalType":"address[]","name":"_tokenDelegates","type":"address[]"}],"name":"removeTokenDelegate","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_tokenContractAddress","type":"address"},{"internalType":"uint256","name":"_tokenID","type":"uint256"},{"internalType":"address","name":"_signer","type":"address"},{"internalType":"bytes","name":"_signature","type":"bytes"}],"name":"signNFT","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"}]`);

 // Unpkg imports
const Web3Modal = window.Web3Modal.default;
const WalletConnectProvider = window.WalletConnectProvider.default;
const Fortmatic = window.Fortmatic;
const evmChains = window.evmChains;

// Web3modal instance
let web3Modal

// Chosen wallet provider given by the dialog window
let provider;

// Address of the selected account
let selectedAccount;

const contractAddress = "0x123";
/**
 * Setup the orchestra
 */
function init() {

  console.log("Initializing example");
  console.log("WalletConnectProvider is", WalletConnectProvider);
  console.log("window.web3 is", window.web3, "window.ethereum is", window.ethereum);

  // Check that the web page is run in a secure context,
  // as otherwise MetaMask won't be available
  if(location.protocol !== 'https:') {
    // https://ethereum.stackexchange.com/a/62217/620
    const alert = document.querySelector("#alert-error-https");
    alert.style.display = "block";
    document.querySelector("#btn-connect").setAttribute("disabled", "disabled")
    return;
  }

  // Tell Web3modal what providers we have available.
  // Built-in web browser provider (only one can exist as a time)
  // like MetaMask, Brave or Opera is added automatically by Web3modal
  const providerOptions = {
    walletconnect: {
      package: WalletConnectProvider,
      options: {
        infuraId: "7669f8c3dc8a4b4d99196daf30d2c8eb",
      }
    }
  };

  web3Modal = new Web3Modal({
    cacheProvider: false, // optional
    providerOptions, // required
    disableInjectedProvider: false, // optional. For MetaMask / Brave / Opera.
  });

  console.log("Web3Modal instance is", web3Modal);
}


/**
 * Kick in the UI action after Web3modal dialog has chosen a provider
 */
async function fetchAccountData() {

  // Get a Web3 instance for the wallet
  const web3 = new Web3(provider);

  console.log("Web3 instance is", web3);

  // Get connected chain id from Ethereum node
  const chainId = await web3.eth.getChainId();
  // Load chain information over an HTTP API
  //const chainData = evmChains.getChain(chainId);
  //document.querySelector("#network-name").textContent = chainData.name;

  // Get list of accounts of the connected wallet
  const accounts = await web3.eth.getAccounts();
  let sigNFTContract = new web3.eth.Contract(jsonABI, '0x9b1f7F645351AF3631a656421eD2e40f2802E6c0', null);
  // MetaMask does not give you all accounts, only the selected account
  console.log("Got accounts", accounts);
  selectedAccount = accounts[0];

  document.querySelector("#selected-account").textContent = selectedAccount;

  // Get a handle
  const template = document.querySelector("#template-balance");
  const accountContainer = document.querySelector("#accounts");

  // Purge UI elements any previously loaded accounts
  accountContainer.innerHTML = '';

  // Go through all accounts and get their ETH balance
  const rowResolvers = accounts.map(async (address) => {
    const balance = await web3.eth.getBalance(address);
    // ethBalance is a BigNumber instance
    // https://github.com/indutny/bn.js/
    const ethBalance = web3.utils.fromWei(balance, "ether");
    const humanFriendlyBalance = parseFloat(ethBalance).toFixed(4);
    // Fill in the templated row and put in the document
    const clone = template.content.cloneNode(true);
    clone.querySelector(".address").textContent = address;
    clone.querySelector(".balance").textContent = humanFriendlyBalance;
    accountContainer.appendChild(clone);
  });

  // Because rendering account does its own RPC commucation
  // with Ethereum node, we do not want to display any results
  // until data for all accounts is loaded
  await Promise.all(rowResolvers);

  //let contractOwner = await sigNFTContract.methods.owner().call();
  //document.querySelector("#owner-acc").textContent = contractOwner;

  // Display fully loaded UI for wallet data
  document.querySelector("#prepare").style.display = "none";
  document.querySelector("#connected").style.display = "block";
  var msg = "This NFT (ID: " + 7 + ", Contract: " + "0x5b1869D9A4C187F2EAa108f3062412ecf0526b24".toLowerCase() + ") was signed by " + selectedAccount.toLowerCase() + " on sigNFT!";
  web3.eth.personal.sign(msg, selectedAccount, function(err, res) {
    if(!err) {
      console.log(res)
      web3.eth.personal.ecRecover(msg, res, function (err1, res2) {
        console.log(res2 + "  " + err1)
      });
    } else {
      console.log(err)
    }
  });

}



/**
 * Fetch account data for UI when
 * - User switches accounts in wallet
 * - User switches networks in wallet
 * - User connects wallet initially
 */
async function refreshAccountData() {

  // If any current data is displayed when
  // the user is switching acounts in the wallet
  // immediate hide this data
  document.querySelector("#connected").style.display = "none";
  document.querySelector("#prepare").style.display = "block";

  // Disable button while UI is loading.
  // fetchAccountData() will take a while as it communicates
  // with Ethereum node via JSON-RPC and loads chain data
  // over an API call.
  document.querySelector("#btn-connect").setAttribute("disabled", "disabled")
  await fetchAccountData(provider);
  document.querySelector("#btn-connect").removeAttribute("disabled")
}


/**
 * Connect wallet button pressed.
 */
async function onConnect() {

  console.log("Opening a dialog", web3Modal);
  try {
    provider = await web3Modal.connect();
  } catch(e) {
    console.log("Could not get a wallet connection", e);
    return;
  }

  // Subscribe to accounts change
  provider.on("accountsChanged", (accounts) => {
    fetchAccountData();
  });

  // Subscribe to chainId change
  provider.on("chainChanged", (chainId) => {
    fetchAccountData();
  });

  // Subscribe to networkId change
  provider.on("networkChanged", (networkId) => {
    fetchAccountData();
  });

  await refreshAccountData();
}

/**
 * Disconnect wallet button pressed.
 */
async function onDisconnect() {

  console.log("Killing the wallet connection", provider);

  // TODO: Which providers have close method?
  if(provider.close) {
    await provider.close();

    // If the cached provider is not cleared,
    // WalletConnect will default to the existing session
    // and does not allow to re-scan the QR code with a new wallet.
    // Depending on your use case you may want or want not his behavir.
    await web3Modal.clearCachedProvider();
    provider = null;
  }

  selectedAccount = null;

  // Set the UI back to the initial state
  document.querySelector("#prepare").style.display = "block";
  document.querySelector("#connected").style.display = "none";
}


/**
 * Main entry point.
 */
window.addEventListener('load', async () => {
  init();
  document.querySelector("#btn-connect").addEventListener("click", onConnect);
  document.querySelector("#btn-disconnect").addEventListener("click", onDisconnect);
});
