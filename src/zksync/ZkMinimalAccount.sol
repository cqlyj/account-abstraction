// SPDX-License-Identifier: MIT

import {IAccount, Transaction, MemoryTransactionHelper, ACCOUNT_VALIDATION_SUCCESS_MAGIC} from "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/IAccount.sol";
import {SystemContractsCaller} from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/SystemContractsCaller.sol";
import {NONCE_HOLDER_SYSTEM_CONTRACT} from "lib/foundry-era-contracts/src/system-contracts/contracts/Constants.sol";
import {INonceHolder} from "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/INonceHolder.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

pragma solidity 0.8.25;

// Lifecycle of a type 113/0x71 transaction:
// msg.sender is always the bootloader system contract whenever you send a type 113 transaction

// Validation:
// 1. The user sends the transaction to the "zkSync API client"
// 2. The "zkSync API client" checks to see the nonce is unique by querying the NonceHolder system contract
// 3. The "zkSync API client" calls validateTransaction, which must update the nonce
// 4. The "zkSync API client" checks the nonce is updated
// 5. The "zkSync API client" calls payForTransaction, or prepareForPaymaster and validateAndPayForPaymasterTransaction
// 6. The "zkSync API client" verifies that the bootloader gets paid

// Execution:
// 7. The "zkSync API client" passes the validated transaction to the main node / sequencer (as if today they are the same)
// 8. The main node / sequencer calls executeTransaction

contract ZKMinimalAccount is IAccount, Ownable {
    using MemoryTransactionHelper for Transaction;

    error ZKMinimalAccount__NotEnoughBalance();

    constructor() Ownable(msg.sender) {}

    /*//////////////////////////////////////////////////////////////
                           EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice We must update the nonce in this function
     * @notice We must validate the transaction in this function => check the owner signed the transaction
     * @notice also check if we have enough money in our account
     */
    function validateTransaction(
        bytes32 /*_txHash*/,
        bytes32 /*_suggestedSignedHash*/,
        Transaction memory _transaction
    ) external payable returns (bytes4 magic) {
        // call nonce holder => system contract call
        // increase the nonce
        SystemContractsCaller.systemCallWithPropagatedRevert(
            uint32(gasleft()),
            address(NONCE_HOLDER_SYSTEM_CONTRACT),
            0,
            abi.encodeCall(
                INonceHolder.incrementMinNonceIfEquals,
                (_transaction.nonce)
            )
        );

        // check for fee to pay
        uint256 totalRequiredBalance = _transaction.totalRequiredBalance();
        if (totalRequiredBalance > address(this).balance) {
            revert ZKMinimalAccount__NotEnoughBalance();
        }

        // check the signature
        bytes32 txHash = _transaction.encodeHash();
        bytes32 convertedHash = MessageHashUtils.toEthSignedMessageHash(txHash);
        address signer = ECDSA.recover(convertedHash, _transaction.signature);
        bool isValidSigner = signer == owner();
        if (isValidSigner) {
            magic = ACCOUNT_VALIDATION_SUCCESS_MAGIC;
        } else {
            magic = bytes4(0);
        }

        // return the magic number
        return magic;
    }

    function executeTransaction(
        bytes32 _txHash,
        bytes32 _suggestedSignedHash,
        Transaction memory _transaction
    ) external payable {}

    // There is no point in providing possible signed hash in the `executeTransactionFromOutside` method,
    // since it typically should not be trusted.
    function executeTransactionFromOutside(
        Transaction memory _transaction
    ) external payable {}

    function payForTransaction(
        bytes32 _txHash,
        bytes32 _suggestedSignedHash,
        Transaction memory _transaction
    ) external payable {}

    function prepareForPaymaster(
        bytes32 _txHash,
        bytes32 _possibleSignedHash,
        Transaction memory _transaction
    ) external payable {}

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/
}
