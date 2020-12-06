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

        // Check whether the signature matches and whether the signed message is correct, e.g.:
        // This NFT (ID: 18756, Contract: 0x0123012301012301230101230123010123012301) was signed by 0x5123012301012301230101230123010123012301 on sigNFT!
        // to protect from replaying the signature
        string memory signedMessage = string(abi.encodePacked(
            "This NFT (ID: ",
            uintToString(_tokenID), 
            ", Contract: ", 
            addressToString(_tokenContractAddress), 
            ") was signed by ", 
            addressToString(_signer), 
            " on sigNFT!"
        ));

        bytes32 messageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n",
            uintToString(bytes(signedMessage).length),
            signedMessage
        ));
        address signer = messageHash.recover(_signature);
        require(signer == _signer, "SIGNFT/WRONG-SIGNATURE");

        // Users can only sign an NFT once
        require(!hasSignedNFT[_tokenContractAddress][_tokenID][signer], "SIGNFT/ALREADY-SIGNED");
        
        // Check whether the token really exists (done in the ownerOf call)
        require(erc721.ownerOf(_tokenID) != address(0), "SIGNFT/TOKEN-DOESNT-EXIST");
        
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
                "SIGNFT/NOT-AUTHORIZED-TO-SIGN"
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
                // The whitelist has been toggled off OR
                (tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].toggled && 
                tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].whitelist) ||
                // The whitelist is off by default and not toggled on
                (!tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].toggled &&
                whitelistIsDefault[_tokenContractAddress]),
                "SIGNFT/WHITELIST-NOT-ACTIVE"
        );

        // This can either be done if you are the owner of the token (if token contract is not controlled by
        // a controller), or by the controller
        if(notDelegated[_tokenContractAddress]) {
            IERC721 erc721 = IERC721(_tokenContractAddress);
            require(erc721.ownerOf(_tokenID) == msg.sender, "SIGNFT/ONLY-CURRENT-TOKEN-OWNER");
        } else {
            require(
                contractDelegate[_tokenContractAddress][msg.sender] || 
                tokenDelegate[_tokenContractAddress][_tokenID][msg.sender], 
                "SIGNFT/ONLY-DELEGATE"
            );
        }

        for(uint256 i = 0; i < _whitelistedSigners.length; i++) { 
            whitelistedSigner[_tokenContractAddress][_tokenID][_whitelistedSigners[i]] = true;
        }
    }

    // Removes people from the whitelist of the token
    function removeFromWhitelist(address _tokenContractAddress, uint256 _tokenID, address[] memory _whitelistedSigners) public {
        require(
                // The whitelist has been toggled off OR
                (tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].toggled && 
                tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].whitelist) ||
                // The whitelist is off by default and not toggled on
                (!tokenIsUsingWhitelist[_tokenContractAddress][_tokenID].toggled &&
                whitelistIsDefault[_tokenContractAddress]),
                "SIGNFT/WHITELIST-NOT-ACTIVE"
        );

        // This can either be done if you are the owner of the token (if token contract is not controlled by
        // a controller), or by the controller
        if(notDelegated[_tokenContractAddress]) {
            IERC721 erc721 = IERC721(_tokenContractAddress);
            require(erc721.ownerOf(_tokenID) == msg.sender, "SIGNFT/ONLY-CURRENT-TOKEN-OWNER");
        } else {
            require(
                contractDelegate[_tokenContractAddress][msg.sender] || 
                tokenDelegate[_tokenContractAddress][_tokenID][msg.sender], 
                "SIGNFT/ONLY-DELEGATE"
            );
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
            require(erc721.ownerOf(_tokenID) == msg.sender, "SIGNFT/ONLY-CURRENT-TOKEN-OWNER");
        } else {
            require(
                contractDelegate[_tokenContractAddress][msg.sender] || 
                tokenDelegate[_tokenContractAddress][_tokenID][msg.sender], 
                "SIGNFT/ONLY-DELEGATE"
            );
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
            require(erc721.ownerOf(_tokenID) == msg.sender, "SIGNFT/ONLY-CURRENT-TOKEN-OWNER");
        } else {
            require(
                contractDelegate[_tokenContractAddress][msg.sender] || 
                tokenDelegate[_tokenContractAddress][_tokenID][msg.sender], 
                "SIGNFT/ONLY-DELEGATE"
            );
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
                require(_contractDelegates[i] != msg.sender, "SIGNFT/CANT-BE-DELEGATE-YOURSELF");
                contractDelegate[_tokenContractAddress][_contractDelegates[i]] = true;
            }
        } else {
            notDelegated[_tokenContractAddress] = true;
        }

        whitelistIsDefault[_tokenContractAddress] = _whitelistAsDefault;
    }

    // Adds delegates for a token contract
    function addContractDelegates(address _tokenContractAddress, address[] memory _contractDelegates) public {
        require(contractDelegate[_tokenContractAddress][msg.sender] || owner() == msg.sender, "SIGNFT/NOT-A-CONTRACT-DELEGATE");
        for(uint256 i = 0; i < _contractDelegates.length; i++) {
                contractDelegate[_tokenContractAddress][_contractDelegates[i]] = true;
        }
    }

    // Removes delegates of a token contract
    function removeContractDelegates(address _tokenContractAddress, address[] memory _contractDelegates) public {
        require(contractDelegate[_tokenContractAddress][msg.sender] || owner() == msg.sender, "SIGNFT/NOT-A-CONTRACT-DELEGATE");
        for(uint256 i = 0; i < _contractDelegates.length; i++) {
                contractDelegate[_tokenContractAddress][_contractDelegates[i]] = false;
        }
    }

    // Change the default whitelist setting for a token contract
    function changeWhitelistDefault(address _tokenContractAddress, bool _whitelistAsDefault) public {
        require(contractDelegate[_tokenContractAddress][msg.sender] || owner() == msg.sender, "SIGNFT/NOT-A-CONTRACT-DELEGATE");
        whitelistIsDefault[_tokenContractAddress] = _whitelistAsDefault;
    }

    // Adds delegates for tokens
    function addTokenDelegate(address _tokenContractAddress, uint256[] memory _tokenIDs, address[] memory _tokenDelegates) public {
        require(contractDelegate[_tokenContractAddress][msg.sender], "SIGNFT/NOT-A-CONTRACT-DELEGATE");
        require(_tokenIDs.length == _tokenDelegates.length, "SIGNFT/ARRAY-LENGTH-MISMATCH");

        for(uint256 i = 0; i < _tokenDelegates.length; i++) {
                tokenDelegate[_tokenContractAddress][_tokenIDs[i]][_tokenDelegates[i]] = true;
        }
    }

    // Remove delegates of tokens
    function removeTokenDelegate(address _tokenContractAddress, uint256[] memory _tokenIDs, address[] memory _tokenDelegates) public {
        require(contractDelegate[_tokenContractAddress][msg.sender], "SIGNFT/NOT-A-CONTRACT-DELEGATE");
        require(_tokenIDs.length == _tokenDelegates.length, "SIGNFT/ARRAY-LENGTH-MISMATCH");

        for(uint256 i = 0; i < _tokenDelegates.length; i++) {
                tokenDelegate[_tokenContractAddress][_tokenIDs[i]][_tokenDelegates[i]] = false;
        }
    }

    // From https://github.com/provable-things/ethereum-api/blob/master/oraclizeAPI_0.5.sol
    function uintToString(uint256 _i) internal pure returns (string memory _uintAsString) {
        if (_i == 0) {
            return "0";
        }
        uint256 j = _i;
        uint256 len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint256 k = len - 1;
        while (_i != 0) {
            bstr[k--] = byte(uint8(48 + _i % 10));
            _i /= 10;
        }
        return string(bstr);
    }

    function addressToString(address _address) internal pure returns(string memory) {
       bytes32 _bytes = bytes32(uint256(_address));
       bytes memory HEX = "0123456789abcdef";
       bytes memory _string = new bytes(42);
       _string[0] = '0';
       _string[1] = 'x';
       for(uint i = 0; i < 20; i++) {
           _string[2+i*2] = HEX[uint8(_bytes[i + 12] >> 4)];
           _string[3+i*2] = HEX[uint8(_bytes[i + 12] & 0x0f)];
       }
       return string(_string);
    }
}