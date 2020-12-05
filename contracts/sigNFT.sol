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
        bytes signature;
    }

    // Stores whether a whitelist has been toggled, to differentiate between
    // the default whitelist mode and toggled mode
    struct WhitelistToggle {
        bool toggled;
        bool whitelist;
    }  

    // Signatures
    // TokenAddress => TokenID => Signature
    mapping (address => mapping (uint256 => Signature[])) internal signatures;
    // TokenAddress => TokenID => SignerAddress => Index 
    mapping (address => mapping (uint256 => mapping (address => uint256))) internal signatureIndexOfSigner;
    // TokenAddress => TokenID => SignerAddress => true/false
    mapping (address => mapping (uint256 => mapping (address => bool))) internal hasSignedNFT;

    // Whitelisting
    // TokenAddress => true/false
    mapping (address => bool) internal whitelistIsDefault;
    // TokenAddress => TokenID => SignerAddress => true/false
    mapping (address => mapping (uint256 => mapping (address => bool))) internal whitelistedSigner;
    // TokenAddress => TokenID => Custom Whitelist Mode true/false
    mapping (address => mapping (uint256 => WhitelistToggle)) internal tokenIsUsingWhitelist;

    // Contract Delegates
    // TokenAddress => ContractDelegate => true/false
    mapping (address => mapping(address => bool)) internal contractDelegate;
    // TokenAddress => true/false
    mapping (address => bool) internal notDelegated;
    // TokenAddress => true/false
    mapping (address => bool) internal contractActivated;

    // Token Delegates
    // TokenAddress => TokenID => TokenDelegate => true/false
    mapping (address => mapping (uint256 => mapping (address => bool))) internal tokenDelegate;

    function initialize() public initializer {
        OwnableUpgradeable.__Ownable_init();
    }

    // signNFT allows people to attach a signatures to an NFT token
    // They have to be either whitelisted (if the token works with a whitelist)
    // or everyone can sign if it's not a token using a whitelist
    function signNFT(address _tokenContractAddress, uint256 _tokenID, address _signer, bytes memory _signature) public {
        IERC721 erc721 = IERC721(_tokenContractAddress);

        // Check the signature
        bytes32 messageHash = keccak256(abi.encodePacked("This NFT (ID: ", _tokenID, ", Contract: ", _tokenContractAddress, ") was signed by ", _signer, " on sigNFT!"));
        address signer = messageHash.recover(_signature);
        require(signer == _signer, "Wrong signature");

        // Users can only sign an NFT once
        require(!hasSignedNFT[_tokenContractAddress][_tokenID][signer], "Already signed by sender");
        
        // Check whether the token really exists (done in the ownerOf call)
        require(erc721.ownerOf(_tokenID) != address(0), "Token doesn't exist");
        
        // Check whether the signer authorized
        require(
                // The signer is whitelisted themselves OR
                whitelistedSigner[_tokenContractAddress][_tokenID][signer] ||
                // The whitelist has been toggled off OR
                (tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].toggled && 
                !tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].whitelist) ||
                // The whitelist is off by default and not toggled on OR
                (!tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].toggled &&
                !whitelistIsDefault[_tokenContractAddress]) ||
                // The user or signer is a contractDelegate OR
                (contractDelegate[_tokenContractAddress][signer] ||
                contractDelegate[_tokenContractAddress][msg.sender]) &&
                // The user or signer is a tokenDelegate
                (tokenDelegate[_tokenContractAddress][_tokenID][signer] ||
                tokenDelegate[_tokenContractAddress][_tokenID][msg.sender]),
                "Not autorized to sign"
        );

        // Store the signer and the signature
        Signature memory newSignature = Signature(signer, _signature);
        signatures[_tokenContractAddress][_tokenID].push(newSignature);
        signatureIndexOfSigner[_tokenContractAddress][_tokenID][signer] = signatures[_tokenContractAddress][_tokenID].length - 1;
        hasSignedNFT[_tokenContractAddress][_tokenID][signer] = true;
    }

    // getSigners returns all signers of a token
    function getSigners(address _tokenContractAddress, uint256 _tokenID) public view returns(address[] memory signersOfToken) {
        signersOfToken = new address[](signatures[_tokenContractAddress][_tokenID].length);

        for(uint256 i = 0; i < signatures[_tokenContractAddress][_tokenID].length; i++) {
            signersOfToken[i] = signatures[_tokenContractAddress][_tokenID][i].signer;
        }

        return signersOfToken;
    }

    // getSignatures returns all signers of a token with their signatures
    function getSignatures(address _tokenContractAddress, uint256 _tokenID) public view returns(address[] memory signersOfToken, bytes[] memory signaturesOfToken) {
        signersOfToken = new address[](signatures[_tokenContractAddress][_tokenID].length);
        signaturesOfToken = new bytes[](signatures[_tokenContractAddress][_tokenID].length);

        for(uint256 i = 0; i < signatures[_tokenContractAddress][_tokenID].length; i++) {
            signersOfToken[i] = signatures[_tokenContractAddress][_tokenID][i].signer;
            signaturesOfToken[i] = signatures[_tokenContractAddress][_tokenID][i].signature;
        }

        return (signersOfToken, signaturesOfToken);
    }

    // Adds people to the whitelist of the token
    function addToWhiteList(address _tokenContractAddress, uint256 _tokenID, address[] memory _whitelistedSigners) public {
        require(
                (tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].toggled && 
                tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].whitelist) ||
                (!tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].toggled &&
                whitelistIsDefault[_tokenContractAddress]),
                "Whitelist is not active"
        );

        // This can either be done if you are the owner of the token (if token contract is not controlled by
        // a controller), or by the controller
        if(notDelegated[_tokenContractAddress]) {
            IERC721 erc721 = IERC721(_tokenContractAddress);
            require(erc721.ownerOf(_tokenID) == msg.sender, "Can't modify whitelist of other tokens");
        } else {
            require(contractDelegate[_tokenContractAddress][msg.sender], "Only controllers are allowed to modify the whitelist");
        }

        for(uint256 i = 0; i < _whitelistedSigners.length; i++) { 
            whitelistedSigner[_tokenContractAddress][_tokenID][_whitelistedSigners[i]] = true;
        }
    }

    // Removes people from the whitelist of the token
    function removeFromWhitelist(address _tokenContractAddress, uint256 _tokenID, address[] memory _whitelistedSigners) public {
        require(
                (tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].toggled && 
                tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].whitelist) ||
                (!tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].toggled &&
                whitelistIsDefault[_tokenContractAddress]),
                "Whitelist is not active"
        );

        // This can either be done if you are the owner of the token (if token contract is not controlled by
        // a controller), or by the controller
        if(notDelegated[_tokenContractAddress]) {
            IERC721 erc721 = IERC721(_tokenContractAddress);
            require(erc721.ownerOf(_tokenID) == msg.sender, "Can't modify whitelist of other tokens");
        } else {
            require(contractDelegate[_tokenContractAddress][msg.sender], "Only controllers are allowed to modify the whitelist");
        }

        for(uint256 i = 0; i < _whitelistedSigners.length; i++) { 
            whitelistedSigner[_tokenContractAddress][_tokenID][_whitelistedSigners[i]] = false;
        }
    }

    // Activates the whitelist of a token
    // If the token contract is controlled by a controller, only they can
    // do this, otherwise it's the current owner
    function activateWhitelist(address _tokenContractAddress, uint256 _tokenID) public {
        if(notDelegated[_tokenContractAddress]) {
            IERC721 erc721 = IERC721(_tokenContractAddress);
            require(erc721.ownerOf(_tokenID) == msg.sender, "Can't modify whitelist of other tokens");
        } else {
            require(contractDelegate[_tokenContractAddress][msg.sender], "Only controllers are allowed to modify the whitelist");
        }

        tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].toggled = true;
        tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].whitelist = true;
    }

    // Deactivates the whitelist of a token
    // If the token contract is controlled by a controller, only they can
    // do this, otherwise it's the current owner
    function deactivateWhitelist(address _tokenContractAddress, uint256 _tokenID) public {
        if(notDelegated[_tokenContractAddress]) {
            IERC721 erc721 = IERC721(_tokenContractAddress);
            require(erc721.ownerOf(_tokenID) == msg.sender, "Can't modify whitelist of other tokens");
        } else {
            require(contractDelegate[_tokenContractAddress][msg.sender], "Only controllers are allowed to modify the whitelist");
        }

        tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].toggled = true;
        tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].whitelist = false;
    }

    // Activates a token contract to work with this contract
    // Currently only the admin can do this, to prevent spamming/abuse
    // The admin itself can't be a controller though, so they can't
    // abuse their power
    // Also allows to set whether the contracts' tokens are whitelisted
    // by default or not
    function activateTokenContract(address _tokenContractAddress, address[] memory _contractDelegates, bool _whitelistAsDefault) public onlyOwner() {
        contractActivated[_tokenContractAddress] = true;

        if(_contractDelegates.length > 0){
            for(uint256 i = 0; i < _contractDelegates.length; i++) {
                require(_contractDelegates[i] != msg.sender, "Can't set yourself as a controller");
                contractDelegate[_tokenContractAddress][_contractDelegates[i]] = true;
            }
        } else {
            notDelegated[_tokenContractAddress] = true;
        }

        whitelistIsDefault[_tokenContractAddress] = _whitelistAsDefault;
    }

    // Adds delegates for a token contract
    function addContractDelegates(address _tokenContractAddress, address[] memory _contractDelegates) public {
        require(contractDelegate[_tokenContractAddress][msg.sender] || owner() == msg.sender, "Not allowed to modify controllers");
        for(uint256 i = 0; i < _contractDelegates.length; i++) {
                contractDelegate[_tokenContractAddress][_contractDelegates[i]] = true;
        }
    }

    // Removes delegates of a token contract
    function removeContractDelegates(address _tokenContractAddress, address[] memory _contractDelegates) public {
        require(contractDelegate[_tokenContractAddress][msg.sender] || owner() == msg.sender, "Not allowed to modify controllers");
        for(uint256 i = 0; i < _contractDelegates.length; i++) {
                contractDelegate[_tokenContractAddress][_contractDelegates[i]] = false;
        }
    }

    // Change the default whitelist setting for a token contract
    function changeWhitelistDefault(address _tokenContractAddress, bool _whitelistAsDefault) public {
        require(contractDelegate[_tokenContractAddress][msg.sender] || owner() == msg.sender, "Not allowed to modify whitelist default setting");
        whitelistIsDefault[_tokenContractAddress] = _whitelistAsDefault;
    }

    // Adds delegates for tokens
    function addTokenDelegate(address _tokenContractAddress, uint256[] memory _tokenIDs, address[] memory _tokenDelegates) public {
        require(contractDelegate[_tokenContractAddress][msg.sender], "Not allowed to modify controllers");
        require(_tokenIDs.length == _tokenDelegates.length, "Array length mismatch");

        for(uint256 i = 0; i < _tokenDelegates.length; i++) {
                tokenDelegate[_tokenContractAddress][_tokenIDs[i]][_tokenDelegates[i]] = true;
        }
    }

    // Remove delegates of tokens
    function removeTokenDelegate(address _tokenContractAddress, uint256[] memory _tokenIDs, address[] memory _tokenDelegates) public {
        require(contractDelegate[_tokenContractAddress][msg.sender], "Not allowed to modify controllers");
        require(_tokenIDs.length == _tokenDelegates.length, "Array length mismatch");

        for(uint256 i = 0; i < _tokenDelegates.length; i++) {
                tokenDelegate[_tokenContractAddress][_tokenIDs[i]][_tokenDelegates[i]] = false;
        }
    }
}