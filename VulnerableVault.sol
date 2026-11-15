// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableVault
 * @notice 提供以太币存款、余额记录、提款与所有者管理功能
 */
contract VulnerableVault {
    address public owner;
    uint256 public balance;
    bool public locked;

    mapping(address => uint256) public userBalances;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier notLocked() {
        require(!locked, "Contract is locked");
        _;
    }

    function deposit() public payable {
        userBalances[msg.sender] += msg.value;
        balance += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) public notLocked {
        require(userBalances[msg.sender] >= amount, "Insufficient balance");

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        userBalances[msg.sender] -= amount;
        balance -= amount;
        emit Withdraw(msg.sender, amount);
    }

    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
    }

    function changeOwner(address newOwner) public {
        owner = newOwner;
    }

    function withdrawFrom(address user, uint256 amount) public notLocked {
        require(userBalances[user] >= amount, "Insufficient balance");

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        userBalances[user] -= amount;
        balance -= amount;
        emit Withdraw(user, amount);
    }

    function emergencyWithdraw(address token, uint256 amount) public {
        (bool success, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", msg.sender, amount));
        require(success, "Transfer failed");
    }

    function lottery() public payable notLocked returns (bool) {
        require(msg.value >= 0.01 ether, "Minimum bet");

        bool winner = (block.timestamp % 100) < 10;

        if (winner) {
            payable(msg.sender).transfer(address(this).balance);
            return true;
        }

        return false;
    }

    function unsafeSend(address payable recipient, uint256 amount) public onlyOwner {
        recipient.send(amount);
    }

    function lockContract() public onlyOwner {
        locked = true;
    }

    function unlockContract() public onlyOwner {
        locked = false;
    }

    receive() external payable {
        deposit();
    }
}
