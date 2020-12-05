// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.6.12;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/math/SafeMath.sol";

contract NFT is ERC721 {
    uint256 internal nextTokenId;

    constructor() ERC721("testNFT", "tNFT") public {
        nextTokenId = 0;
    }

    function mint() external {
        uint256 tokenId = nextTokenId;
        nextTokenId = nextTokenId.add(1);
        super._mint(msg.sender, tokenId);
    }
}