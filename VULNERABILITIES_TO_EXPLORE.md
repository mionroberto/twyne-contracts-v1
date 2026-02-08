# Twyne Protocol - Vulnerabilita' da Esplorare per Immunefi Bug Bounty

**Data:** 8 Febbraio 2026
**Scope:** Ethereum Mainnet - Contratti deployati dal CollateralVaultFactory

---

## Regole Immunefi - Classificazione

### IN SCOPE (Impact qualificanti)
- **CRITICAL**: Furto diretto di fondi utente, freeze permanente, insolvenza protocollo
- **HIGH**: Freeze temporaneo >=24h, furto yield non reclamato, freeze permanente yield

### OUT OF SCOPE (Esclusi esplicitamente)
- **Rischi di centralizzazione** (governance rug, admin key compromise)
- **Attacchi da indirizzi privilegiati** senza modifica addizionale dei privilegi
- **Dati oracolo errati** da terze parti (MA non esclude manipolazione oracolo/flash loan)
- **Impatti di liquidita'** (mancanza liquidita' nel vault intermedio)
- **Issues note**: vulnerabilita' Euler ereditate, fallimento credit reservation, cambio LTV esterni, mancanza slippage check

---

## SEZIONE A: Finding del Report Precedente - Reclassificazione

### F-01: Vault Freeze Permanente con Prezzo Oracolo = 0
- **Precedente classificazione**: CRITICAL
- **Status Immunefi**: BORDERLINE
- **PoC Status**: CONFERMATO - `test_poc_F01_permanentFreezeOracleZero()` PASS
- **Risultato PoC**: Con prezzo WETH=0, `canLiquidate()` ritorna true. repay() funziona ancora. Il problema e' nell'intero flusso: dopo liquidazione esterna Euler, `handleExternalLiquidation()` richiede socializzazione bad debt via `intermediateVault.liquidate()`, ma con prezzo 0 questo fallisce (confermato in `EulerTestEdgeCases.t.sol:950-953`).
- **Argomento per IN-SCOPE**: Il protocollo dovrebbe gestire gracefully QUALSIASI output dell'oracolo. L'assenza di una funzione di emergenza per risolvere bad debt e' un difetto di design del protocollo, non un difetto dell'oracolo.

### F-02/F-03/F-04/F-07/F-08: Governance/Centralizzazione
- **Status Immunefi**: OUT OF SCOPE
- **Motivo**: Tutte richiedono accesso a indirizzi privilegiati.

### F-05: externalLiqBuffer = 1e4 nel deployment
- **Status Immunefi**: OUT OF SCOPE - Configurazione governance.

### F-06: Oracle Stale dopo Riconfigurazione Euler
- **Status Immunefi**: OUT OF SCOPE - "Incorrect data supplied by third party oracles".

### F-09: HealthStatViewer.health() Underflow
- **Status Immunefi**: OUT OF SCOPE - Funzione view-only, nessun impatto su fondi.

### F-10: T_DebtMoreThanMax Errore Non Definito
- **Status Immunefi**: OUT OF SCOPE
- **CONFERMATO**: Il build Foundry fallisce con `Error (7576): Undeclared identifier. Did you mean "T_DebtMoreThanMin"?` alla riga 128 di DeleverageOperator.sol. Il contratto NON COMPILA con il codice sorgente attuale.

### checkLiqLTV Condizione Impossibile (finding esterno)
- **Status Immunefi**: OUT OF SCOPE - Richiede governance che imposti maxTwyneLTVs troppo basso.

---

## SEZIONE B: Risultati PoC - Vettori di Attacco Esterni

### B-01: Flash Loan Exchange Rate Manipulation su eToken
- **Status**: TESTATO - **SAFE**
- **PoC**: `test_poc_B01_exchangeRateManipulation()` - PASS
- **Risultato**: Exchange rate INVARIATO dopo deposit di 1000 ETH in eulerWETH (1012474319545914436 prima e dopo). Le shares vengono mintate proporzionalmente, quindi un deposit non cambia il rate.
- **PoC aggiuntivo**: `test_poc_B01b_donationAttack()` - PASS
- **Risultato**: EVK ignora donazioni dirette (usa contabilita' interna, non balanceOf). Exchange rate invariato dopo transfer di 100 ETH a eulerWETH.
- **Conclusione**: NON SFRUTTABILE - EVK ha protezioni robuste contro manipolazione exchange rate.

### B-02: EVC Batch come Flash Loan Gratuito
- **Status**: TESTATO - **SAFE**
- **PoC**: `test_poc_B02_evcBatchFreeFlashLoan()` - PASS
- **Risultato**: Il batch deposit->borrow->repay->withdraw funziona (USDC change=0, eWETH change=0). MA gli items del batch sono sequenziali senza possibilita' di inserire chiamate esterne tra di essi.
- **PoC aggiuntivo**: `test_poc_B02b_evcBatchWithExternalCall()` - PASS
- **Risultato**: Batch separati (deposit+borrow poi repay+withdraw) sono semplicemente borrowing normale. L'utente ha collaterale a rischio.
- **Conclusione**: NON SFRUTTABILE - I batch items non permettono interleaving di call esterne. Borrowing+repaying nel batch e' un no-op.

### B-03: handleExternalLiquidation Reward Manipulation
- **Status**: TESTATO - **SAFE**
- **PoC**: `test_poc_B03_liquidationRewardFairness()` - PASS
- **Risultato**: Bonus liquidatore = 7% (con maxTwyneLTV=9300). Questo e' nello standard industriale (Aave 5-10%, Compound 8%). Il reward e' protetto da `Math.min(_collateralBalance, ...)`. Non c'e' modo di estrarre piu' del collaterale disponibile.
- **Conclusione**: NON SFRUTTABILE - Formula fair, protetta matematicamente.

### B-04: Teleport con toDeposit=0, toBorrow>0
- **Status**: TEST INCONCLUSIVE (errore setup EVC)
- **PoC**: `test_poc_B04_teleportZeroDeposit()` - FAIL (EVC_InvalidAddress)
- **Causa fallimento**: Il test usa DUE EVC distinte (Twyne EVC per il collateral vault, Euler EVC on-chain per i vault Euler). La configurazione del batch su Euler EVC fallisce durante il setup, non durante il teleport.
- **Analisi statica**: Con `toDeposit=0, toBorrow>0`:
  1. `totalAssetsDepositedOrReserved` non cambia (+0)
  2. `_handleExcessCredit` aggiusta credito basandosi sullo stato PRE-teleport
  3. Il batch Euler borra dal targetVault (aumenta debito) e ripaga il subAccount
  4. `checkVaultStatus` alla fine chiama `_canLiquidate()` che vede il debito aumentato
  5. Con debito aumentato e collaterale invariato → `_canLiquidate()` ritorna true → revert `VaultStatusLiquidatable`
- **Conclusione**: PROBABILMENTE SAFE - Il health check deferred DOVREBBE catturare l'inconsistenza, ma serve conferma con test funzionante.

### B-05: balanceOf() Manipulation via Interest Accrual
- **Status**: ANALIZZATO - **SAFE**
- **Analisi**: `maxRelease = Math.min(debtOf, totalAssets)` previene underflow. Con LTV 100% e BridgeHookTarget che blocca liquidazione, manipolazione del debtOf non ha impatto diretto. Dopo handleExternalLiquidation, `totalAssets=0` e il check `borrower==address(0)` gestisce il caso correttamente.
- **Conclusione**: NON SFRUTTABILE

### B-06: Operator swapData Arbitrary Call
- **Status**: ANALIZZATO - **SAFE**
- **Analisi**: SWAPPER e' immutabile, impostato a Euler's official swapper. Anche se multicall permette call generiche, il collateral vault ha `nonReentrant` che blocca reentrancy. Il LeverageOperator ha `ReentrancyGuardTransient`. Le call esterne dal swapper non possono rientrare nel protocollo Twyne.
- **Conclusione**: NON SFRUTTABILE - Protezione reentrancy multi-livello.

### B-07: convertToAssets 1:1 Pricing
- **Status**: VERIFICATO nel PoC B-01 - **SAFE**
- **Analisi**: Il PoC B-01 ha confermato che l'oracle risolve correttamente la catena: CollateralVault (1:1) → eToken (convertToAssets) → underlying → Chainlink. Il prezzo totale per 1e18 eWETH = 2074015068318231022805 (corretto). La manipolazione dell'exchange rate non funziona (confermato).
- **Conclusione**: Pricing corretto.

### B-08: rebalance() MEV
- **Status**: ANALIZZATO - **OUT OF SCOPE**
- **Analisi**: rebalance() ripaga eccesso, rendendo la posizione piu' sana. Impatto sulla utilization rate e' "liquidity-related" (escluso da Immunefi).
- **Conclusione**: Out of scope.

---

## SEZIONE C: Riepilogo Finale

### Vulnerabilita' Sfruttabili da Attaccante Esterno: NESSUNA CONFERMATA

Dopo analisi approfondita con PoC Foundry su mainnet fork (blocco 22440000):

| ID | Vettore | Risultato PoC | Verdict |
|----|---------|---------------|---------|
| B-01 | Exchange Rate Flash Loan | SAFE | Shares proporzionali + internal accounting |
| B-01b | Donation Attack | SAFE | EVK ignora donazioni |
| B-02 | EVC Batch Flash Loan | SAFE | No interleaving di call esterne |
| B-03 | Liquidation Reward | SAFE | 7% bonus, Math.min protection |
| B-04 | Teleport Zero Deposit | INCONCLUSIVE | Analisi statica suggerisce safe |
| B-05 | balanceOf Manipulation | SAFE | Math.min previene underflow |
| B-06 | swapData Arbitrary Call | SAFE | Multi-layer reentrancy protection |
| B-07 | convertToAssets Pricing | SAFE | Catena risoluzione corretta |
| B-08 | rebalance MEV | OUT OF SCOPE | Liquidity-related |

### Unico Finding Borderline per Immunefi

**F-01: Permanent Vault Freeze con Oracle Price = 0**
- Confermato funzionalmente (test esistente + nostro PoC)
- Impatto: Permanent freezing of funds (CRITICAL in Immunefi)
- Causa root: Oracle returns 0 (potenzialmente "incorrect oracle data" = OUT)
- Argomento: il BUG e' nel protocollo (no emergency fallback), non nell'oracolo
- **Probabilita' di accettazione Immunefi: 30-50%**

### Bug di Compilazione Confermato

**F-10: T_DebtMoreThanMax undefined** - Il build Foundry conferma che `DeleverageOperator.sol` non compila con il codice sorgente attuale. Errore: `Undeclared identifier "T_DebtMoreThanMax"`. Questo e' un bug reale ma probabilmente non in-scope per Immunefi (nessun impatto su fondi).
