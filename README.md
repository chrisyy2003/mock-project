# Mock Solidity Project for Security Testing

独立 Web/API 安全测试靶场见 [web-api-mock/](./web-api-mock/README.md)。该靶场使用
研究访问密钥和合成测试账号保护，包含明确标注的 XSS、IDOR 和 SQL 注入测试缺陷；
不连接本仓库合约、不使用真实业务数据，不可作为生产应用部署。

## 概述

这个项目包含故意设计有安全漏洞的智能合约，用于测试 ZeroDrift 安全审计工具的功能。

## 合约

### VulnerableVault.sol

包含多个常见安全漏洞的金库合约：

#### 🔴 严重漏洞
1. **重入攻击** (withdraw) - 状态更新在外部调用之前
2. **访问控制缺失** (changeOwner) - 任何人都可以更改 owner

#### 🟡 中等漏洞
3. **逻辑错误** (withdrawFrom) - 可以提取其他用户的余额
4. **前端运行** (emergencyWithdraw) - 可以任意调用外部合约
5. **时间依赖** (lottery) - 使用 block.timestamp 作为随机数

#### 🟢 低级漏洞
6. **未检查的返回值** (unsafeSend) - send 失败不会回滚
7. **不安全的数学运算** (unsafeAdd) - 演示数学运算问题
8. **缺少安全检查** - 缺少零地址检查等基础验证

## 使用方法

### 1. 安装 ZeroDrift GitHub App
```bash
# 访问前端页面
https://zerodrift.xyz/audit

# 点击 "Install GitHub App"
# 在 GitHub 页面选择此仓库进行授权
```

### 2. 运行安全审计
```bash
# 在前端页面选择此仓库
# 选择 VulnerableVault.sol 文件
# 点击 "Pay with Credits" 开始审计
```

## 预期审计结果

ZeroDrift 应该能够检测到以下安全问题：

- Reentrancy vulnerability
- Access control issues
- Front-running attacks
- Time manipulation
- Unchecked return values
- Logic errors
- Unsafe mathematical operations

## 测试目的

这个合约仅用于测试和演示目的，不应在生产环境中使用。所有漏洞都是故意设计的，用于验证安全审计工具的有效性。

## 贡献

这是一个测试项目，不需要贡献。如有问题，请联系 ZeroDrift 团队。

## 许可证

MIT License
