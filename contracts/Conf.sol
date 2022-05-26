// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "./Verifier.sol";

contract Confidential is ERC20, Verifier{

    mapping (address => uint[2]) balanceHashes;

    constructor(uint256 initialSupply) ERC20("TOKEN", "SS"){

    _mint(msg.sender, initialSupply);
    balanceHashes[msg.sender] =   [267155370138219963795935159289233917406, 297982103872684426429258885425731138599];

    }

    function TRANFER(address _to, Proof memory proofSender, Proof memory proofReceiver, uint hashSenderBalanceAfter_1, uint hashSenderBalanceAfter_2, uint hashValue_1, uint hashValue_2, uint hashReceiverBalanceAfter_1, uint hashReceiverBalanceAfter_2, uint boo) public {

    address to = _to;     

    uint[2] memory hashSenderBalanceBefore = balanceHashes[msg.sender];
    if(balanceHashes[to][0] == uint(0) && balanceHashes[to][1] == uint(0)){
        balanceHashes[to] = [326522724692461750427768532537390503835, 89059515727727869117346995944635890507];
    }
    
    uint[2] memory hashReceiverBalanceBefore = balanceHashes[_to];
    uint[8] memory inputSender = [uint(0), hashSenderBalanceBefore[0], hashSenderBalanceBefore[1], hashSenderBalanceAfter_1, hashSenderBalanceAfter_2, hashValue_1, hashValue_2, boo];
    uint[8] memory inputReceiver = [uint(1), hashReceiverBalanceBefore[0], hashReceiverBalanceBefore[1], hashReceiverBalanceAfter_1, hashReceiverBalanceAfter_2, hashValue_1, hashValue_2, boo];

    bool senderProofIsCorrect = verifyTx(proofSender, inputSender);
    bool receiverProofIsCorrect = verifyTx(proofReceiver, inputReceiver); 

    if (senderProofIsCorrect && receiverProofIsCorrect){

        balanceHashes[msg.sender] = [hashSenderBalanceAfter_1, hashSenderBalanceAfter_2];
        balanceHashes[to] = [hashReceiverBalanceAfter_1, hashReceiverBalanceAfter_2];

    }

    }

    function BALANCE_OF(address _account) public view returns (uint[2] memory){

        return balanceHashes[_account];
    
    }





}

