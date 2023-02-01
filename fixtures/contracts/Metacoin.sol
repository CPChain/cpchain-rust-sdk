// SPDX-License-Identifier: MIT
// Tells the Solidity compiler to compile only from v0.8.13 to v0.9.0
pragma solidity ^0.4.24;

// This is just a simple example of a coin-like contract.
// It is not ERC20 compatible and cannot be expected to talk to other
// coin/token contracts.

contract MetaCoin {
    mapping(address => uint256) balances;

    event Transfer(address indexed _from, address _to, uint256 _value, string s, bool b, uint128 i, uint64 i2, uint32 i3, uint16 i4, uint8 i5);

    constructor() public {
        balances[tx.origin] = 10000;
    }

    function sendCoin(address receiver, uint256 amount)
        public
        returns (bool sufficient)
    {
        if (balances[msg.sender] < amount) return false;
        balances[msg.sender] -= amount;
        balances[receiver] += amount;
        emit Transfer(msg.sender, receiver, amount, "Hello", true, 128, 64, 32, 16, 8);
        return true;
    }

    function getBalance(address addr) public view returns (uint256) {
        return balances[addr];
    }
}
