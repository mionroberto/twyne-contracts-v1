# Twyne Protocol - Security Audit Report

**Auditors:** Security Audit Team
**Date:** February 8, 2026
**Scope:** All contracts in `src/`, deployment scripts in `script/`
**Chain:** Ethereum Mainnet, Base
**Methodology:** Manual code review, cross-contract interaction analysis, deployment configuration verification

---

## Executive Summary

This report covers a comprehensive security audit of the Twyne Protocol v1, built on Euler Finance's EVC and EVK infrastructure. The audit analyzed **10 Solidity contracts** (1,692 lines of source code), **10 deployment scripts** (1,733 lines), and **11 test files** (7,655 lines).

The protocol architecture is sound with strong defense-in-depth: reentrancy protection (OpenZeppelin + EVK guards), bounded arithmetic via `Math.min`, deferred health checks through EVC, and proper initialization of UUPS proxies. However, significant **centralization and governance risks** were identified, along with one externally exploitable edge case.

### Findings Summary

| ID | Severity | Title | Category |
|----|----------|-------|----------|
| F-01 | CRITICAL | Permanent Vault Freeze When Oracle Returns Zero Price | External |
| F-02 | CRITICAL | `doCall()` Enables Instant Hook Removal, Exposing 100% LTV Positions | Governance |
| F-03 | CRITICAL | `doCall()` Enables Oracle Manipulation for Mass Liquidations | Governance |
| F-04 | CRITICAL | UUPS + Beacon Upgrade Without Timelock | Governance |
| F-05 | HIGH | `externalLiqBuffer = 1e4` Eliminates Safety Margin (Deployed Config) | Configuration |
| F-06 | HIGH | Stale Oracle After Euler Reconfiguration | External Dependency |
| F-07 | HIGH | Post-Creation Parameter Changes Invalidate Existing Vault Invariants | Governance |
| F-08 | HIGH | Combined Pause + Hook Disable Can Freeze All User Funds | Governance |
| F-09 | MEDIUM | `HealthStatViewer.health()` Underflow Reverts Break Frontends | Code Bug |
| F-10 | MEDIUM | `DeleverageOperator` Uses Undefined Error `T_DebtMoreThanMax` | Code Bug |
| F-11 | LOW | `IRMTwyneCurve` Constructor Allows Underflowing Parameter Combinations | Code Bug |

---

## Detailed Findings

---

### F-01: CRITICAL - Permanent Vault Freeze When Oracle Returns Zero Price During External Liquidation

**Affected Code:**
- `src/twyne/CollateralVaultBase.sol:244-258` (`checkVaultStatus`)
- `src/twyne/EulerCollateralVault.sol:185-234` (`handleExternalLiquidation`)

**Description:**

When a collateral vault is externally liquidated by Euler and the collateral asset's oracle price drops to zero (or the oracle reverts), the bad debt settlement flow becomes permanently blocked:

1. `handleExternalLiquidation()` sets `borrower = address(0)` and `totalAssetsDepositedOrReserved = 0`
2. `checkVaultStatus()` requires `intermediateVault.debtOf(this) == 0` when `borrower == address(0)`
3. The batch must include `intermediateVault.liquidate()` to socialize bad debt
4. EVK's `liquidate()` needs the oracle to value the liability -- with a zero price, it cannot recognize the debt
5. Bad debt is never socialized, `checkVaultStatus` always reverts, the entire batch reverts atomically

The vault enters a permanent frozen state:
- `totalAssetsDepositedOrReserved > IERC20(asset).balanceOf(this)` (externally liquidated)
- All functions with `onlyBorrowerAndNotExtLiquidated` revert (deposit, withdraw, borrow, repay)
- `handleExternalLiquidation` cannot complete because bad debt socialization fails
- Any remaining collateral in the vault is permanently locked

**Evidence:** This scenario is explicitly tested and acknowledged in `test/twyne/EulerTestEdgeCases.t.sol:950-953`:
```solidity
// Since liability value is 0 (asset price is 0), bad debt isn't recognized
// and not settled in items[1]. Thus, intermediateVault.debt(collateralVault) is non-zero
vm.expectRevert(TwyneErrors.BadDebtNotSettled.selector);
evc.batch(items);
```

**Attack Scenario:**
1. Alice has a collateral vault with eWETH collateral and USDC borrow
2. Extreme black swan: WETH price crashes to near-zero, or Chainlink feed is decommissioned
3. Euler externally liquidates the position
4. No one can call `handleExternalLiquidation` successfully
5. Remaining collateral is permanently frozen

**Impact:** Permanent fund freezing. Protocol insolvency for affected vaults.

**Recommendation:** Add a governance-callable emergency function that can force-settle bad debt when the oracle is non-functional, or allow `handleExternalLiquidation` to succeed even when bad debt socialization fails (with the bad debt tracked separately).

---

### F-02: CRITICAL - `doCall()` Enables Instant Hook Removal, Exposing 100% LTV Positions to Direct Liquidation

**Affected Code:**
- `src/twyne/VaultManager.sol:163-170` (`doCall`)
- `src/TwyneFactory/CollateralVaultFactory.sol:111` (hardcoded 100% LTV)
- `src/TwyneFactory/BridgeHookTarget.sol:26-29` (`liquidate` hook)

**Description:**

VaultManager is the `governorAdmin` of all intermediate vaults. The `doCall()` function (onlyOwner) enables arbitrary calls from VaultManager's address. The owner can call:

```solidity
vaultManager.doCall(
    address(intermediateVault), 0,
    abi.encodeCall(IEVault.setHookConfig, (address(0), 0))
);
```

This instantly removes BridgeHookTarget, which is the **sole mechanism** preventing direct EVK liquidation of collateral vault positions. All collateral vaults are created with a hardcoded LTV of `1e4` (100%) on the intermediate vault:

```solidity
// CollateralVaultFactory.sol:111
vaultManager.setLTV(IEVault(intermediateVault), vault, 1e4, 1e4, 0);
```

Without the hook, any external actor can liquidate every collateral vault position at the 100% LTV threshold with a 20% liquidation discount (`maxLiquidationDiscount = 0.2e4`).

**Impact:** Direct theft of all user funds deposited into collateral vaults. Single-transaction governance rug vector with no timelock.

**Note:** This requires compromised governance (multisig). While Immunefi typically considers governance rug vectors out of scope, the absence of any timelock means users have zero opportunity to exit before the attack completes.

**Recommendation:** Add a timelock to `doCall()`, or restrict which contracts/functions it can target, or remove the function entirely and replace with specific governance actions.

---

### F-03: CRITICAL - `doCall()` Enables Oracle Manipulation for Mass Illegitimate Liquidations

**Affected Code:**
- `src/twyne/VaultManager.sol:62-65` (`setOracleRouter`), `163-170` (`doCall`)
- `src/twyne/EulerCollateralVault.sol:141-145` (oracle in `_canLiquidate`)

**Description:**

The owner can inject a malicious oracle adapter via `doCall`:

```solidity
vaultManager.doCall(
    address(oracleRouter), 0,
    abi.encodeCall(EulerRouter.govSetConfig, (WETH, USD, maliciousOracle))
);
```

Or replace the entire oracle router: `vaultManager.setOracleRouter(maliciousOracle)`.

A malicious oracle reporting very low collateral values would make all positions appear undercollateralized in `_canLiquidate()`. The permissionless `liquidate()` function then allows the attacker to seize all collateral vaults.

**Impact:** Direct theft of all user funds via mass illegitimate liquidations.

**Note:** Requires compromised governance. Same timelock recommendation as F-02.

---

### F-04: CRITICAL - UUPS + Beacon Upgrade Without Timelock Enables Instant Malicious Implementation Swap

**Affected Code:**
- `src/twyne/VaultManager.sol:54` (`_authorizeUpgrade` - empty body, onlyOwner)
- `src/TwyneFactory/CollateralVaultFactory.sol:45` (same pattern)

**Description:**

Both VaultManager and CollateralVaultFactory use UUPS upgradeability with an empty `_authorizeUpgrade(address) internal override onlyOwner {}`. The owner can atomically upgrade to any implementation.

Additionally, the UpgradeableBeacon for collateral vaults is owned by the admin. A beacon upgrade changes the implementation for ALL existing collateral vaults simultaneously, as demonstrated in the test (`test/twyne/EulerTestEdgeCases.t.sol:384-393`):

```solidity
beacon.upgradeTo(address(new NewImplementation()));
assertEq(alice_collateral_vault.version(), 953); // Changed instantly
```

Positive: All implementation contracts correctly call `_disableInitializers()` in constructors.

**Impact:** Complete control over all protocol contracts and user funds. Permanent theft or freezing of all assets.

**Recommendation:** Add a timelock (48h+) on all upgrade paths. Consider using OpenZeppelin's `TimelockController`.

---

### F-05: HIGH - `externalLiqBuffer = 1e4` Eliminates Safety Margin Between Twyne and Euler Liquidation

**Affected Code:**
- `script/TwyneDeployEulerIntegration.s.sol:342`
- `src/twyne/EulerCollateralVault.sol:81, 124`

**Description:**

The initial deployment sets `externalLiqBuffer = 1e4` (100%) for eulerWETH:

```solidity
vaultManager.setExternalLiqBuffer(eulerWETH, 1e4);
```

This means Twyne's liquidation condition 1 triggers at exactly the same threshold as Euler's external liquidation. There is zero buffer. A Twyne liquidator who takes over a vault has no margin before Euler liquidates the position externally, potentially creating irrecoverable bad debt.

Later deployment scripts (`TwyneAddVaultPair.s.sol:330-334`) use `0.99e4` (99%), providing a 1% buffer. The initial deployment has no such protection.

**Impact:** Liquidation race conditions leading to bad debt socialized to Credit LPs. Temporary fund freezing during conflicting liquidation attempts.

**Recommendation:** Set a minimum buffer (e.g., `0.95e4`) and enforce it in `setExternalLiqBuffer`.

---

### F-06: HIGH - Stale Oracle After Euler Reconfiguration

**Affected Code:**
- `script/TwyneDeployEulerIntegration.s.sol:202-204`
- `src/twyne/EulerCollateralVault.sol:141-145`

**Description:**

During deployment, Twyne copies oracle addresses from Euler's router:

```solidity
address eulerExternalOracle = EulerRouter(IEVault(_asset).oracle())
    .getConfiguredOracle(IEVault(_asset).asset(), USD);
```

This is a snapshot. If Euler subsequently updates their oracle (e.g., migrating Chainlink feeds), Twyne still points to the old oracle contract. If the old feed is decommissioned:

- All Twyne operations depending on pricing revert (`_canLiquidate`, `_invariantCollateralAmount`, deposits, withdrawals)
- Every collateral vault becomes frozen until governance updates the oracle
- In the interim, positions that should be liquidated are not, creating bad debt risk

**Impact:** Temporary freezing of all collateral vaults (potentially >24h). Undercollateralized positions avoiding liquidation.

**Recommendation:** Implement an oracle freshness check, or add a monitoring mechanism that alerts when Euler's oracle diverges from Twyne's.

---

### F-07: HIGH - Post-Creation Parameter Changes Invalidate Existing Vault Invariants

**Affected Code:**
- `src/twyne/VaultManager.sol:115-129` (`setMaxLiquidationLTV`, `setExternalLiqBuffer`)
- `src/twyne/EulerCollateralVault.sol:79-84` (`_invariantCollateralAmount`)

**Description:**

`_invariantCollateralAmount()` reads `externalLiqBuffers` dynamically:

```solidity
uint liqLTV_external = uint(IEVault(targetVault).LTVLiquidation(asset()))
    * uint(twyneVaultManager.externalLiqBuffers(asset()));
```

Governance changes to `externalLiqBuffers` or `maxTwyneLTVs` take immediate effect on all existing vaults without retroactive validation. Setting `externalLiqBuffer` to `1` (the minimum allowed) would make `liqLTV_external` ~10,000x smaller than expected, causing `_invariantCollateralAmount` to return an enormous value. This forces `_handleExcessCredit` to borrow massive amounts from the intermediate vault, potentially draining LP deposits.

With `externalLiqBuffer = 1`, liquidation condition 1 becomes:
- `debtValue * 10000 > 1 * collateralValue` -- TRUE for virtually every position

Every position with any debt becomes instantly liquidatable.

**Impact:** Mass liquidation of all user positions. Theft of user collateral by liquidators.

**Recommendation:** Enforce a meaningful minimum on `externalLiqBuffer` (e.g., `0.90e4`) rather than allowing values as low as 1.

---

### F-08: HIGH - Combined Pause + Hook Disable Can Permanently Freeze All User Funds

**Affected Code:**
- `src/TwyneFactory/CollateralVaultFactory.sol:76-79` (`pause`)
- `src/twyne/CollateralVaultBase.sol:318-334` (`withdraw` calls `_handleExcessCredit`)

**Description:**

While `withdraw()` intentionally lacks `whenNotPaused` (allowing user exit during pause), it internally calls `_handleExcessCredit()` which calls `intermediateVault.repay()` or `intermediateVault.borrow()`. If governance blocks intermediate vault operations via `doCall`:

```solidity
eeWETH_intermediate_vault.setHookConfig(address(0), OP_MAX_VALUE - 1);
```

Then ALL exit paths revert because `_handleExcessCredit` is called by `withdraw`, `repay`, `redeemUnderlying`, and `rebalance`.

This is confirmed in tests (`test/twyne/EulerTestEdgeCases.t.sol:302-326`):
```solidity
vm.expectRevert(Errors.E_OperationDisabled.selector);
alice_collateral_vault.withdraw(1 ether, alice);
```

**Impact:** Temporary or permanent freezing of all user funds. If governance keys are lost, permanent.

---

### F-09: MEDIUM - `HealthStatViewer.health()` Underflow Reverts When Internal Debt Exceeds Collateral Value

**Affected Code:**
- `src/twyne/HealthStatViewer.sol:76`

**Description:**

```solidity
inHF = twyneLiqLTV * (vaultOwnedCollateralValue - internalBorrowDebtValue) * 1e18
    / (externalBorrowDebtValue * MAXFACTOR);
```

When intermediate vault interest accrues between user operations, `internalBorrowDebtValue` can exceed `vaultOwnedCollateralValue`, causing an arithmetic underflow revert. This is a view function only -- on-chain liquidation logic in `_canLiquidate()` is unaffected (it uses different calculation paths).

**Impact:** Frontend and monitoring tools relying on `health()` break for stale positions. Liquidation bots using this view may fail to detect unhealthy positions.

**Recommendation:** Use a checked subtraction that returns 0 when the value would underflow, or return `inHF = 0` when internal debt exceeds collateral value.

---

### F-10: MEDIUM - `DeleverageOperator` Uses Undefined Error `T_DebtMoreThanMax`

**Affected Code:**
- `src/operators/DeleverageOperator.sol:128`
- `src/interfaces/IErrors.sol:37`

**Description:**

`DeleverageOperator.sol` uses `T_DebtMoreThanMax()` at line 128:
```solidity
require(IEVault(targetVault).debtOf(collateralVault) <= maxDebt, T_DebtMoreThanMax());
```

But `IErrors.sol` only defines `T_DebtMoreThanMin()` (line 37). `DeleverageOperator` inherits from `IErrors`. The error `T_DebtMoreThanMax` is not defined anywhere in the codebase.

In Solidity 0.8.28, custom errors used in `require` statements must be explicitly defined. If this code compiles, it may be due to a Solidity version quirk or the error being implicitly generated. If it does NOT compile, the DeleverageOperator has never been deployed from this source.

**Impact:** Either compilation failure (meaning DeleverageOperator is non-functional) or error name mismatch causing incorrect off-chain error decoding.

**Recommendation:** Rename the error definition in `IErrors.sol` to `T_DebtMoreThanMax` or update the reference in `DeleverageOperator.sol`.

---

### F-11: LOW - `IRMTwyneCurve` Constructor Allows Underflowing Parameter Combinations

**Affected Code:**
- `src/twyne/IRMTwyneCurve.sol:47-48`

**Description:**

```solidity
linearParameter = idealKinkInterestRate * MAXFACTOR / linearKinkUtilizationRate_;
polynomialParameter = maxInterestRate_ - linearParameter;
```

When `idealKinkInterestRate * MAXFACTOR / linearKinkUtilizationRate > maxInterestRate`, the subtraction underflows. Example: `idealKinkInterestRate = 40000, linearKinkUtilizationRate = 5000, maxInterestRate = 50000` yields `linearParameter = 80000`, causing `50000 - 80000` to underflow.

**Impact:** Constructor reverts. No runtime risk. Deployment ergonomics issue only.

---

## Areas Verified Secure

The following areas were thoroughly analyzed and found to be robust:

### Reentrancy Protection
- Triple-layer protection: CollateralVaultBase `nonReentrant`, EVK `nonReentrant`, and `nonReentrantView` for view functions
- Snapshot mechanism (`createVaultSnapshot`/`checkVaultStatus`) correctly integrates with EVC deferred checks

### Liquidation Arithmetic
- `Math.min` in `maxRelease()` prevents `totalAssetsDepositedOrReserved - maxRelease()` from underflowing
- `splitCollateralAfterExtLiq` uses `Math.min(_collateralBalance, ...)` to cap liquidator reward
- All subsequent subtractions (`releaseAmount`, `borrowerClaim`) are bounded by prior `Math.min` operations

### Teleport Function
- Sub-account XOR matches Euler's EVC convention (0-255 sub-accounts)
- Missing allowance causes clean revert (no partial state)
- Deferred health check catches invalid final states

### Operator Contracts
- Flashloan callbacks properly validate `msg.sender == MORPHO`
- Data decoded from callbacks originates from validated sources within `executeLeverage`/`executeDeleverage`
- `nonReentrant` (transient) prevents concurrent access
- No residual tokens remain in operator contracts between transactions
- User-controlled `swapData` can only invoke trusted SWAPPER's multicall

### Factory Salt Security
- `keccak256(abi.encodePacked(msgSender, nonce[msgSender]++))` prevents front-running
- `msgSender` is EVC-authenticated, nonce is per-user and atomically incremented

### EulerWrapper
- WETH transfer is safe (WETH9 always returns true)
- EVK skim is atomic within transaction (no front-running possible)
- User-supplied `intermediateVault` can only harm the caller's own funds

### BridgeHookTarget
- `borrow()` correctly restricts to registered collateral vaults
- `liquidate()` correctly requires `borrower == address(0)` (post-external liquidation)
- `fallback()` blocks all other hooked operations
- Flashloan is blocked by the fallback

---

## Architecture Observations

1. **Single-owner governance without timelock**: VaultManager and CollateralVaultFactory are owned by a multisig with no on-chain delay for critical operations. The `doCall()` function provides unrestricted arbitrary call capability. While multisig governance is standard, the combination with instant upgradeability and `doCall` creates a significant rug vector.

2. **100% LTV hardcode depends on hook**: The intermediate vault sets collateral vault LTV to 100% (`1e4`). This is only safe because BridgeHookTarget blocks direct liquidation. If the hook is removed (via `doCall` or upgrade), all positions are instantly at liquidation threshold. This is a fragile invariant.

3. **Shared EVC**: The protocol correctly shares Euler's EVC instance (not two separate EVCs). This is critical for the EVC batch-and-check model to work across Twyne and Euler operations.

4. **Debt socialization dependency**: The bad debt settlement path requires EVK's `liquidate()` to function correctly. When oracle prices are zero, this path fails, creating an unrecoverable state (F-01).

---

## Recommendations Priority

| Priority | Action |
|----------|--------|
| P0 | Add emergency function for bad debt settlement when oracle fails (F-01) |
| P0 | Add timelock (48h+) to `doCall()`, UUPS upgrades, and beacon upgrades (F-02, F-03, F-04) |
| P1 | Enforce minimum `externalLiqBuffer >= 0.90e4` (F-05, F-07) |
| P1 | Implement oracle synchronization monitoring with Euler (F-06) |
| P1 | Fix `T_DebtMoreThanMax` error definition (F-10) |
| P2 | Add checked subtraction in `HealthStatViewer.health()` (F-09) |
| P2 | Separate emergency withdrawal path that doesn't require `_handleExcessCredit` (F-08) |
| P3 | Add constructor validation for IRM parameter overflow (F-11) |
