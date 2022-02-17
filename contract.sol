// SPDX-License-Identifier: GPL-3.0

import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/master/contracts/access/Ownable.sol";
import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/master/contracts/utils/cryptography/ECDSA.sol";

pragma solidity ^0.8.4;

contract SignedTokenVerifier {
    using ECDSA for bytes32;

    address private _signer;

    event SignerUpdated(address newSigner);

    constructor(address _initialSigner) {
        _signer = _initialSigner;
    }

    function _setSigner(address _newSigner) internal {
        _signer = _newSigner;
        emit SignerUpdated(_signer);
    }

    function _hash(string calldata salt, address _address)
        internal
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(salt, address(this), _address));
    }

    function _verify(bytes32 hash, bytes memory token)
        internal
        view
        returns (bool)
    {
        return (_recover(hash, token) == _signer);
    }

    function _recover(bytes32 hash, bytes memory token)
        internal
        pure
        returns (address)
    {
        return hash.toEthSignedMessageHash().recover(token);
    }

    function verifyTokenForAddress(
        string calldata _salt,
        bytes calldata _token,
        address _address
    ) public view returns (bool) {
        return _verify(_hash(_salt, _address), _token);
    }
}

contract SignatureNFTMint is Ownable, SignedTokenVerifier {
    constructor(address _signer) SignedTokenVerifier(_signer) {}

    event Minted(address _to, uint256 _tokenId);

    error InvalidToken();

    function whitelistMint(string calldata _salt, bytes calldata _token)
        external
    {
        if (!verifyTokenForAddress(_salt, _token, msg.sender))
            revert InvalidToken();
        emit Minted(msg.sender, 1);
    }

    function setSigner(address _newSigner) external onlyOwner {
        _setSigner(_newSigner);
    }
}
