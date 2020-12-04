// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.6.12;
pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts-ethereum-package/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts-ethereum-package/contracts/cryptography/ECDSA.sol";
import "@openzeppelin/contracts-ethereum-package/contracts/math/SafeMath.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract sigNFT is OwnableUpgradeable {
    using SafeMath for uint256;
    using ECDSA for bytes32;

    // Stores the actual signature together with the signers address
    struct Signature {
        address signer;
        string message;
    }

    // Stores whether a whitelist has been toggled, to differentiate between
    // the default whitelist mode and toggled mode
    struct WhitelistToggle {
        bool toggled;
        bool whitelist;
    }  

    // Signatures
    mapping (address => mapping (uint256 => Signature[])) internal signatures;
    mapping (address => mapping (uint256 => mapping (address => uint256))) internal signatureIndexOfSigner;
    mapping (address => mapping (address => mapping (uint256 => bool))) internal hasSignedNFT;

    // Whitelisting
    mapping (address => bool) internal whitelistIsDefault;
    mapping (address => mapping (uint256 => mapping (address => bool))) internal whitelistedSigner;
    mapping (address => mapping (uint256 => WhitelistToggle)) internal tokenIsUsingWhitelist;

    // Token Controllers
    mapping (address => mapping(address => bool)) internal contractController;
    mapping (address => bool) internal noController;
    mapping (address => bool) internal contractActive;

    function initialize() public initializer {
        OwnableUpgradeable.__Ownable_init();
    }

    // signNFT allows people to attach a signed message to an NFT token
    // They have to be either whitelisted (if the token works with a whitelist)
    // or everyone can sign if it's not a token using a whitelist
    function signNFT(address _tokenAddress, uint256 _tokenID, string memory _message, bytes memory _signature) public {
        IERC721 erc721 = IERC721(_tokenAddress);
        
        // Check whether the token really exists (done in the ownerOf call)
        require(erc721.ownerOf(_tokenID) != address(0), "Token doesn't exist");
        
        // Check whether the user is
        // a) whitelisted OR
        // b) the whitelist has been toggled to off
        // c) the whitelist was never toggled and is off by default
        require(
                whitelistedSigner[_tokenAddress][_tokenID][msg.sender] ||
                (tokenIsUsingWhitelist[_tokenAddress][_tokenID].toggled && 
                !tokenIsUsingWhitelist[_tokenAddress][_tokenID].whitelist) ||
                (!tokenIsUsingWhitelist[_tokenAddress][_tokenID].toggled &&
                !whitelistIsDefault[_tokenAddress]),
                "Not autorized to sign"
        );

        // Users can only sign an NFT once
        require(!hasSignedNFT[_tokenAddress][msg.sender][_tokenID], "Already signed by sender");

        // Empty Message doesn't work
        require(bytes(_message).length > 0, "Empty message");
        
        // Verify that the signature matches the sender
        bytes32 messageHash = keccak256(abi.encodePacked(_message));
        require(messageHash.recover(_signature) == msg.sender, "Invalid Signature");

        // Store the message and the signature
        Signature memory newSignature = Signature(msg.sender, _message);
        signatures[_tokenAddress][_tokenID].push(newSignature);
        signatureIndexOfSigner[_tokenAddress][_tokenID][msg.sender] = signatures[_tokenAddress][_tokenID].length - 1;
        hasSignedNFT[_tokenAddress][msg.sender][_tokenID] = true;
    }

    // getSignatures returns all signers and their messages of a token
    function getSignatures(address _tokenAddress, uint256 _tokenID) public view returns(address[] memory signers, string[] memory messages) {
        IERC721 erc721 = IERC721(_tokenAddress);
        require(erc721.ownerOf(_tokenID) != address(0), "Token doesn't exist");

        signers = new address[](signatures[_tokenAddress][_tokenID].length);
        messages = new string[](signatures[_tokenAddress][_tokenID].length);

        for(uint256 i = 0; i < signatures[_tokenAddress][_tokenID].length; i++) {
            signers[i] = signatures[_tokenAddress][_tokenID][i].signer;
            messages[i] = signatures[_tokenAddress][_tokenID][i].message;
        }

        return (signers, messages);
    }

    // Adds people to the whitelist of the token
    function addToWhiteList(address _tokenAddress, uint256 _tokenID, address[] memory _whitelistedSigners) public {
        require(
                (tokenIsUsingWhitelist[_tokenAddress][_tokenID].toggled && 
                tokenIsUsingWhitelist[_tokenAddress][_tokenID].whitelist) ||
                (!tokenIsUsingWhitelist[_tokenAddress][_tokenID].toggled &&
                whitelistIsDefault[_tokenAddress]),
                "Whitelist is not active"
        );

        // This can either be done if you are the owner of the token (if token contract is not controlled by
        // a controller), or by the controller
        if(noController[_tokenAddress]) {
            IERC721 erc721 = IERC721(_tokenAddress);
            require(erc721.ownerOf(_tokenID) == msg.sender, "Can't modify whitelist of other tokens");
        } else {
            require(contractController[_tokenAddress][msg.sender], "Only controllers are allowed to modify the whitelist");
        }

        for(uint256 i = 0; i < _whitelistedSigners.length; i++) { 
            whitelistedSigner[_tokenAddress][_tokenID][_whitelistedSigners[i]] = true;
        }
    }

    // Removes people from the whitelist of the token
    function removeFromWhitelist(address _tokenAddress, uint256 _tokenID, address[] memory _whitelistedSigners) public {
        require(
                (tokenIsUsingWhitelist[_tokenAddress][_tokenID].toggled && 
                tokenIsUsingWhitelist[_tokenAddress][_tokenID].whitelist) ||
                (!tokenIsUsingWhitelist[_tokenAddress][_tokenID].toggled &&
                whitelistIsDefault[_tokenAddress]),
                "Whitelist is not active"
        );

        // This can either be done if you are the owner of the token (if token contract is not controlled by
        // a controller), or by the controller
        if(noController[_tokenAddress]) {
            IERC721 erc721 = IERC721(_tokenAddress);
            require(erc721.ownerOf(_tokenID) == msg.sender, "Can't modify whitelist of other tokens");
        } else {
            require(contractController[_tokenAddress][msg.sender], "Only controllers are allowed to modify the whitelist");
        }

        for(uint256 i = 0; i < _whitelistedSigners.length; i++) { 
            whitelistedSigner[_tokenAddress][_tokenID][_whitelistedSigners[i]] = false;
        }
    }

    // Activates the whitelist of a token
    // If the token contract is controlled by a controller, only they can
    // do this, otherwise it's the current owner
    function activateWhitelist(address _tokenAddress, uint256 _tokenID) public {
        if(noController[_tokenAddress]) {
            IERC721 erc721 = IERC721(_tokenAddress);
            require(erc721.ownerOf(_tokenID) == msg.sender, "Can't modify whitelist of other tokens");
        } else {
            require(contractController[_tokenAddress][msg.sender], "Only controllers are allowed to modify the whitelist");
        }

        tokenIsUsingWhitelist[_tokenAddress][_tokenID].toggled = true;
        tokenIsUsingWhitelist[_tokenAddress][_tokenID].whitelist = true;
    }

    // Deactivates the whitelist of a token
    // If the token contract is controlled by a controller, only they can
    // do this, otherwise it's the current owner
    function deactivateWhitelist(address _tokenAddress, uint256 _tokenID) public {
        if(noController[_tokenAddress]) {
            IERC721 erc721 = IERC721(_tokenAddress);
            require(erc721.ownerOf(_tokenID) == msg.sender, "Can't modify whitelist of other tokens");
        } else {
            require(contractController[_tokenAddress][msg.sender], "Only controllers are allowed to modify the whitelist");
        }

        tokenIsUsingWhitelist[_tokenAddress][_tokenID].toggled = true;
        tokenIsUsingWhitelist[_tokenAddress][_tokenID].whitelist = false;
    }

    // Activates a token contract to work with this contract
    // Currently only the admin can do this, to prevent spamming/abuse
    // The admin itself can't be a controller though, so they can't
    // abuse their power
    // Also allows to set whether the contracts' tokens are whitelisted
    // by default or not
    function activateContract(address _tokenAddress, address[] memory _tokenControllers, bool _whitelistAsDefault) public onlyOwner() {
        contractActive[_tokenAddress] = true;
        if(_tokenControllers.length > 0){
            for(uint256 i = 0; i < _tokenControllers.length; i++) {
                require(_tokenControllers[i] != msg.sender, "Can't set yourself as a controller");
                contractController[_tokenAddress][_tokenControllers[i]] = true;
            }
        } else {
            noController[_tokenAddress] = true;
        }

        whitelistIsDefault[_tokenAddress] = _whitelistAsDefault;
    }

    // Adds controllers for a token contract
    function addControllers(address _tokenAddress, address[] memory _tokenControllers) public {
        require(contractController[_tokenAddress][msg.sender] || owner() == msg.sender, "Not allowed to modify controllers");
        for(uint256 i = 0; i < _tokenControllers.length; i++) {
                contractController[_tokenAddress][_tokenControllers[i]] = true;
        }
    }

    // Removes controllers of a token contract
    function removeControllers(address _tokenAddress, address[] memory _tokenControllers) public {
        require(contractController[_tokenAddress][msg.sender] || owner() == msg.sender, "Not allowed to modify controllers");
        for(uint256 i = 0; i < _tokenControllers.length; i++) {
                contractController[_tokenAddress][_tokenControllers[i]] = false;
        }
    }
}