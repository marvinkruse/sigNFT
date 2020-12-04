// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.6.12;
pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import "@openzeppelin/contracts-ethereum-package/contracts/cryptography/ECDSA.sol";
import "@openzeppelin/contracts-ethereum-package/contracts/math/SafeMath.sol";

contract sigNFT is ERC721Upgradeable {
    using SafeMath for uint256;
    using ECDSA for bytes32;

    struct Signature {
        address signer;
        string message;
    }

    mapping (uint256 => Signature[]) internal signatures;
    mapping (uint256 => mapping (address => uint256)) internal signatureIndexOfSigner;
    mapping (address => mapping (uint256 => bool)) internal hasSignedNFT;
    mapping (uint256 => mapping (address => bool)) internal whitelistedSigner;
    mapping (uint256 => bool) internal tokenIsUsingWhitelist;

    function initialize() initializer public {
        __ERC721_init("sigNFT", "sigNFT");
    }

    function signNFT(uint256 _tokenID, string memory _message, bytes memory _signature) public {
        require(_exists(_tokenID), "Token doesn't exist");
        require(!tokenIsUsingWhitelist[_tokenID] || whitelistedSigner[_tokenID][msg.sender], "Not whitelisted to sign");
        require(!hasSignedNFT[msg.sender][_tokenID], "Already signed by sender");
        require(bytes(_message).length > 0, "Empty message");
        
        bytes32 messageHash = keccak256(abi.encodePacked(_message));
        require(messageHash.recover(_signature) == msg.sender, "Invalid Signature");

        Signature memory newSignature = Signature(msg.sender, _message);
        signatures[_tokenID].push(newSignature);
        signatureIndexOfSigner[_tokenID][msg.sender] = signatures[_tokenID].length - 1;
        hasSignedNFT[msg.sender][_tokenID] = true;
    }

    function getSigners(uint256 _tokenID) public view returns(address[] memory signers) {
        require(_exists(_tokenID), "Token doesn't exist");

        signers = new address[](signatures[_tokenID].length);

        for(uint256 i = 0; i < signatures[_tokenID].length; i++) {
            signers[i] = signatures[_tokenID][i].signer;
        }
    }

    function getMessageOfSigner(uint256 _tokenID, address _signer) public view returns(string memory message) {
        require(_exists(_tokenID), "Token doesn't exist");

        uint256 index = signatureIndexOfSigner[_tokenID][_signer];
        require(signatures[_tokenID][index].signer == _signer, "Not a signer");
        return signatures[_tokenID][index].message;
    }

    function getAllSignersAndMessages(uint256 _tokenID) public view returns(address[] memory signers, string[] memory messages) {
        require(_exists(_tokenID), "Token doesn't exist");

        signers = new address[](signatures[_tokenID].length);
        messages = new string[](signatures[_tokenID].length);

        for(uint256 i = 0; i < signatures[_tokenID].length; i++) {
            signers[i] = signatures[_tokenID][i].signer;
            messages[i] = signatures[_tokenID][i].message;
        }

        return (signers, messages);
    }

    function addToWhiteList(uint256 _tokenID, address _whitelistedSigner) public {
        require(ownerOf(_tokenID) == msg.sender, "Can't modify whitelist of other tokens");
        if(!tokenIsUsingWhitelist[_tokenID]) {
            tokenIsUsingWhitelist[_tokenID] = true;
        }
        whitelistedSigner[_tokenID][_whitelistedSigner] = true;
    }

    function removeFromWhitelist(uint256 _tokenID, address _whitelistedSigner) public {
        require(ownerOf(_tokenID) == msg.sender, "Can't modify whitelist of other tokens");
        whitelistedSigner[_tokenID][_whitelistedSigner] = false;
    }

    function activateWhitelist(uint256 _tokenID) public {
        require(ownerOf(_tokenID) == msg.sender, "Can't modify whitelist of other tokens");
        tokenIsUsingWhitelist[_tokenID] = true;
    }

    function deactivateWhitelist(uint256 _tokenID) public {
        require(ownerOf(_tokenID) == msg.sender, "Can't modify whitelist of other tokens");
        tokenIsUsingWhitelist[_tokenID] = false;
    }

    function mint(uint256 _tokenID, bool _whitelistedToken) public {
        _safeMint(msg.sender, _tokenID);
        tokenIsUsingWhitelist[_tokenID] = _whitelistedToken;
    }
}