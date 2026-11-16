# Vault Contract

独立 Web/API 安全测试靶场见 [web-api-mock/](./web-api-mock/README.md)。该靶场使用
研究访问密钥和合成测试账号保护；当前 `fixed-v2` 已修复 XSS、IDOR 和 SQL 注入，
漏洞基线保留于 `d7e11cfc4add67a01055455dc001da1b69198baa`。本地 HTTP 回归与
SaaS 复测分别记录于靶场 README，不连接本仓库合约、不使用真实业务数据，
不可作为生产应用部署。

## 概述

Solidity 金库合约，提供以太币存入、余额记录、提款、转账及所有者管理功能。

## 合约

`VulnerableVault.sol` 包含以下功能：

- 存入以太币并记录用户余额。
- 按指定金额提款，或从指定用户余额中提款。
- 修改所有者，锁定或解锁提款。
- 调用指定合约执行转账。
- 根据区块时间判断奖金领取结果。
- 由所有者发送以太币。

## 编译版本

Solidity `^0.8.0`。

## 许可证

MIT License
