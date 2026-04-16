// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableVault
 * @notice 包含多个安全漏洞的金库合约
 * @dev 用于安全审计测试的故意漏洞合约
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

    // 漏洞 1: 重入攻击 - 使用 call.value 而不是 transfer
    function deposit() public payable {
        userBalances[msg.sender] += msg.value;
        balance += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // 漏洞 2: 重入攻击 - 状态更新在外部调用之前
    function withdraw(uint256 amount) public notLocked {
        require(userBalances[msg.sender] >= amount, "Insufficient balance");

        // 错误：先进行外部调用，然后更新状态
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        userBalances[msg.sender] -= amount;
        balance -= amount;
        emit Withdraw(msg.sender, amount);
    }

    // 漏洞 3: 整数溢出（虽然 Solidity 0.8+ 会自动检查，但逻辑问题仍然存在）
    function unsafeAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b; // 在 0.8+ 版本中会 panic，但演示了不安全的数学运算
    }

    // 漏洞 4: 访问控制问题 - 任何人都可以更改 owner
    function changeOwner(address newOwner) public {
        owner = newOwner; // 缺少 onlyOwner 修饰符
    }

    // 漏洞 5: 逻辑错误 - 可以提取其他用户的余额
    function withdrawFrom(address user, uint256 amount) public notLocked {
        require(userBalances[user] >= amount, "Insufficient balance");

        // 错误：任何人都可以提取任何人的资金
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        userBalances[user] -= amount;
        balance -= amount;
        emit Withdraw(user, amount);
    }

    // 漏洞 6: 前端运行 - 调用者可以控制存储槽位
    function emergencyWithdraw(address token, uint256 amount) public {
        // 错误：没有验证 token 地址，可能导致任意调用
        (bool success, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", msg.sender, amount));
        require(success, "Transfer failed");
    }

    // 漏洞 7: 时间依赖 - 可以通过时间操纵影响逻辑
    function lottery() public payable notLocked returns (bool) {
        require(msg.value >= 0.01 ether, "Minimum bet");

        // 错误：使用 block.timestamp 作为随机数
        bool winner = (block.timestamp % 100) < 10;

        if (winner) {
            payable(msg.sender).transfer(address(this).balance);
            return true;
        }

        return false;
    }

    // 漏洞 8: 未检查的返回值 - send 失败不会回滚
    function unsafeSend(address payable recipient, uint256 amount) public onlyOwner {
        // 错误：send 失败只会返回 false，不会回滚交易
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
