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
- **Motivo**: L'impatto (freeze permanente fondi) E' in scope. La causa root (oracolo restituisce 0) potrebbe essere "dati errati da terze parti" (OUT). Tuttavia il BUG e' nel protocollo: non c'e' fallback quando la socializzazione bad debt fallisce. Anche con prezzo REALMENTE a zero (non dati errati, ma crash reale), il protocollo si rompe permanentemente.
- **Argomento per IN-SCOPE**: Il protocollo dovrebbe gestire gracefully QUALSIASI output dell'oracolo. L'assenza di una funzione di emergenza per risolvere bad debt e' un difetto di design del protocollo, non un difetto dell'oracolo.
- **Priorita' esplorazione**: ALTA - Richiede PoC Foundry che dimostri il freeze permanente
- **Test esistente che lo conferma**: `test/twyne/EulerTestEdgeCases.t.sol:950-953`

### F-02/F-03/F-04/F-07/F-08: Governance/Centralizzazione
- **Status Immunefi**: OUT OF SCOPE
- **Motivo**: Tutte richiedono accesso a indirizzi privilegiati. "Impacts involving centralization risks" e' esplicitamente escluso.

### F-05: externalLiqBuffer = 1e4 nel deployment
- **Status Immunefi**: OUT OF SCOPE
- **Motivo**: Configurazione impostata da governance. Rischio di centralizzazione.

### F-06: Oracle Stale dopo Riconfigurazione Euler
- **Status Immunefi**: OUT OF SCOPE
- **Motivo**: "Incorrect data supplied by third party oracles" + dipendenza esterna Euler.

### F-09: HealthStatViewer.health() Underflow
- **Status Immunefi**: OUT OF SCOPE
- **Motivo**: Funzione view-only, nessun impatto su fondi. Non causa furto, freeze, o insolvenza.

### F-10: T_DebtMoreThanMax Errore Non Definito
- **Status Immunefi**: OUT OF SCOPE (probabilmente)
- **Motivo**: Bug di naming senza impatto diretto su fondi. Se il contratto non compila, il DeleverageOperator non e' stato deployato, e gli utenti possono comunque deleveraggiare manualmente.

### checkLiqLTV Condizione Impossibile (finding esterno)
- **Status Immunefi**: OUT OF SCOPE
- **Motivo**: Richiede governance che imposti maxTwyneLTVs troppo basso. E' un "privileged address attack".

---

## SEZIONE B: Vettori di Attacco ESTERNI da Esplorare

Questi sono i vettori che un attaccante NON privilegiato potrebbe sfruttare e che sono IN SCOPE per Immunefi.

---

### B-01: [ESPLORARE] Flash Loan Exchange Rate Manipulation su eToken

**Ipotesi**: L'attaccante manipola l'exchange rate degli eToken (eulerWETH) tramite flash loan per inflazionare il valore del collaterale Twyne.

**Meccanismo Oracle**:
1. EulerRouter ha `resolvedVaults` - quando prezza un eToken, chiama `eToken.convertToAssets()`
2. EVK `convertToAssets()` = `shares * totalAssets / totalShares`
3. Se un attaccante flash-deposita in eulerWETH, `totalAssets` aumenta, `convertToAssets` ritorna di piu'
4. Questo potrebbe inflazionare il prezzo nella catena di risoluzione dell'oracolo

**Dove viene usato**:
- `_canLiquidate()` condizione 2: `oracleRouter.getQuote(userCollateral, asset, unitOfAccount)` (linea 141-142 EulerCollateralVault.sol)
- `splitCollateralAfterExtLiq()`: `oracleRouter.getQuote(maxRepay, targetAsset, underlyingAsset)` (linea 169-173)
- `_invariantCollateralAmount()`: NON usa l'oracolo direttamente (usa solo parametri LTV)

**Analisi preliminare**: Il valore del collaterale e il valore del debito interno sono entrambi denominati nello STESSO eToken. Se l'exchange rate aumenta, entrambi i lati si gonfiano proporzionalmente, quindi il rapporto LTV resta invariato. PERO':
- Nella condizione 2 di `_canLiquidate()`, `userCollateralValue` e' in USD (convertito dall'oracolo), mentre `externalBorrowDebtValue` viene da `targetVault.accountLiquidity()` che usa l'oracolo di EULER (non di Twyne)
- Se l'oracolo Twyne risolve diversamente da quello Euler, potrebbe esserci una discrepanza

**Da verificare**:
- [ ] Controllare se `targetVault.accountLiquidity()` usa lo stesso percorso di risoluzione oracle
- [ ] Verificare se un flash deposit in eulerWETH puo' cambiare il risultato di `convertToAssets`
- [ ] Testare se la manipolazione dell'exchange rate crea una discrepanza sfruttabile tra i due percorsi oracle
- [ ] Verificare se Euler ha protezione anti-donation/anti-manipulation sull'exchange rate

**Impatto potenziale**: CRITICAL - False liquidazioni / borrowing eccessivo

---

### B-02: [ESPLORARE] EVC Batch - Temporary State Exploitation

**Ipotesi**: L'attaccante costruisce un batch EVC che sfrutta l'inconsistenza temporanea dello stato per estrarre valore prima che `checkVaultStatus` venga chiamato.

**Meccanismo**:
- Durante un batch EVC, i vault status check sono DIFFERITI alla fine
- Un attaccante potrebbe: (1) depositare, (2) borroware il massimo, (3) trasferire i fondi presi in prestito, (4) il check alla fine verifica solo lo stato finale

**Analisi preliminare**: Il `checkVaultStatus` alla fine del batch chiama `_canLiquidate()`. Se il vault e' in stato sano alla fine, il batch passa. L'attaccante non puo' beneficiare di uno stato intermedio senza che lo stato finale sia compromesso.

MA: cosa succede se l'attaccante interagisce con ALTRI contratti durante il batch?
- Passo 1: Deposita in vault A (suo)
- Passo 2: Borra il massimo da vault A
- Passo 3: Usa i fondi presi in prestito per manipolare un altro protocollo
- Passo 4: Ripaga il prestito prima che il batch finisca

Questo e' essenzialmente un flash loan gratuito attraverso il sistema Twyne. Il BridgeHookTarget blocca flashloan diretti sull'intermediate vault (`OP_FLASHLOAN` e' hooked). Ma attraverso il batch EVC con deposit+borrow+repay, l'effetto e' lo stesso.

**Da verificare**:
- [ ] Puo' un utente creare un vault, depositare, borroware, e ripagare nel STESSO batch per ottenere un flash loan gratuito?
- [ ] Se si', puo' questo essere usato per manipolare prezzi o stati di altri protocolli?
- [ ] C'e' un costo (interesse) associato a questa operazione atomica?

**Impatto potenziale**: HIGH - Flash loan gratuito tramite il protocollo

---

### B-03: [ESPLORARE] handleExternalLiquidation - Liquidator Reward Manipulation

**Ipotesi**: Il liquidator di handleExternalLiquidation riceve un reward calcolato con l'oracolo. Puo' manipolare la tempistica o le condizioni per massimizzare il reward a discapito del borrower?

**Codice critico** (EulerCollateralVault.sol:164-182):
```solidity
liquidatorReward = oracleRouter.getQuote(
    _maxRepay * MAXFACTOR / maxTwyneLTVs(__asset),
    targetAsset, IEVault(__asset).asset());
liquidatorReward = Math.min(_collateralBalance, IEVault(__asset).convertToShares(liquidatorReward));
```

**Punti da analizzare**:
- Il reward e' `maxRepay / maxTwyneLTV` convertito in collaterale. Con `maxTwyneLTV = 0.94e4`, il reward e' ~106% del debito rimborsato (in valore collaterale). Questo bonus e' giusto?
- `Math.min` protegge contro reward > collaterale totale
- Ma `borrowerClaim = collateralBalance - releaseAmount - liquidatorReward`. Se il reward e' generoso, il borrower perde di piu'
- Puo' un attaccante front-runnare la liquidazione esterna per posizionarsi come liquidator e catturare il reward?

**Scenario di attacco**:
1. Attaccante monitora mempool per liquidazioni Euler su vault Twyne
2. Euler liquida il vault (rimuove collaterale)
3. Attaccante front-runna `handleExternalLiquidation`, ripaga il debito restante, riceve il reward in collaterale
4. Il borrower riceve meno del dovuto

**Da verificare**:
- [ ] Il reward formula e' equa? `maxRepay / maxTwyneLTV` potrebbe dare un reward eccessivo?
- [ ] Confrontare il reward del liquidator con lo standard di mercato (Aave/Compound liquidation bonus)
- [ ] Puo' un attaccante provocare deliberatamente una liquidazione esterna per poi catturare il reward?
- [ ] Cosa succede se `_maxRepay` e' molto piccolo? Il reward potrebbe essere sproporzionato?

**Impatto potenziale**: HIGH - Furto parziale di collaterale del borrower

---

### B-04: [ESPLORARE] Teleport con toDeposit=0 e toBorrow>0

**Ipotesi**: Un borrower usa teleport per aggiungere debito al vault senza collaterale, bypassando i check.

**Codice** (EulerCollateralVault.sol:237-272):
```solidity
totalAssetsDepositedOrReserved += toDeposit; // toDeposit = 0
_handleExcessCredit(_invariantCollateralAmount());
// eulerEVC.batch:
//   items[0]: transferFrom(subAccount, this, 0) - no-op
//   items[1]: borrow(toBorrow, this)            - increases debt
//   items[2]: repay(toBorrow, subAccount)       - repays subAccount
```

**Analisi**: Con `toDeposit = 0`, nessun collaterale aggiuntivo entra nel vault. Ma `items[1]` borra dal targetVault, aumentando il debito esterno del vault. Poi `items[2]` ripaga il debito del subAccount.

Il check alla fine (`evc.requireAccountAndVaultStatusCheck`) dovrebbe catturare l'aumento di debito senza collaterale aggiuntivo. MA:
- Il `_handleExcessCredit` e' chiamato PRIMA del batch eulerEVC, quindi aggiusta il credito basandosi sullo stato PRE-teleport
- Dopo il batch, il debito esterno e' aumentato ma il credito intermedio non e' stato riaggustato
- Il `checkVaultStatus` controlla `_canLiquidate()` che usa lo stato ATTUALE (post-batch)

**Da verificare**:
- [ ] Il checkVaultStatus cattura effettivamente il debito aumentato?
- [ ] C'e' un caso dove il debito migrato rende il vault piu' sano (perche' il subAccount aveva un tasso di interesse piu' alto)?
- [ ] Cosa succede se il subAccount non ha abbastanza collaterale per il transferFrom ma ha debito?

**Impatto potenziale**: CRITICAL - Potenziale aggiunta di debito senza collaterale

---

### B-05: [ESPLORARE] balanceOf() Manipulation via Interest Accrual

**Ipotesi**: L'intermediate vault prezza il collateral vault tramite `balanceOf(this)`. Questa funzione ritorna `totalAssetsDepositedOrReserved - maxRelease()` dove `maxRelease = min(debtOf, totalAssets)`. Il `debtOf` cresce con gli interessi. Puo' un attaccante forzare l'accrual degli interessi per ridurre il `balanceOf` e triggerare una liquidazione sull'intermediate vault?

**Analisi**: Con LTV 100% e BridgeHookTarget che blocca la liquidazione, questo non dovrebbe avere impatto diretto. PERO':
- Se `debtOf` supera `totalAssetsDepositedOrReserved` (teoricamente impossibile ma verificare), `maxRelease = totalAssets` e `balanceOf = 0`
- Con `balanceOf = 0`, l'intermediate vault vede zero collaterale
- Se `borrower == address(0)` (post-handleExternalLiquidation), il BridgeHookTarget PERMETTE la liquidazione

**Da verificare**:
- [ ] Puo' debtOf superare totalAssetsDepositedOrReserved? Normalmente no perche' _handleExcessCredit aggiusta, ma dopo handleExternalLiquidation totalAssets = 0 e debtOf potrebbe essere > 0
- [ ] In questo caso, balanceOf ritorna 0 (c'e' il check esplicito per borrower == address(0))
- [ ] Verificare se c'e' uno scenario dove il debt accrual crea una discrepanza sfruttabile

**Impatto potenziale**: MEDIUM - Probabilmente sicuro, ma verificare edge case

---

### B-06: [ESPLORARE] Operator swapData Arbitrary Call

**Ipotesi**: In LeverageOperator, l'utente controlla `swapData` che viene passato a `SWAPPER.multicall()`. Se SWAPPER permette call arbitrarie, l'utente potrebbe chiamare contratti Twyne durante il flashloan.

**Codice** (LeverageOperator.sol:140):
```solidity
ISwapper(SWAPPER).multicall(swapData);
```

**Analisi**: SWAPPER e' immutabile e impostato al deploy (e' il contratto Euler Swapper ufficiale). La domanda e': cosa puo' fare `multicall` su SWAPPER? Se SWAPPER e' un contratto Euler ufficiale con multicall generico, potrebbe essere usato per:
1. Chiamare il collateral vault durante il flashloan (ma nonReentrant lo blocca)
2. Chiamare l'intermediate vault (possibile, non protetto da nonReentrant del collateral vault)
3. Chiamare altri contratti esterni

**Da verificare**:
- [ ] Analizzare il contratto Euler Swapper: che operazioni permette multicall?
- [ ] Se multicall permette call a qualsiasi contratto, verificare che non ci siano reentrancy cross-contract
- [ ] Il LeverageOperator usa ReentrancyGuardTransient - questo protegge solo l'operator, non altri contratti

**Impatto potenziale**: HIGH - Se multicall e' generico, potenziale reentrancy cross-contract

---

### B-07: [ESPLORARE] convertToAssets 1:1 vs Exchange Rate Reale

**Ipotesi**: `CollateralVault.convertToAssets()` ritorna 1:1 (1 share = 1 asset). Ma il vault detiene eTokens che hanno un exchange rate variabile. Se l'exchange rate dell'eToken cambia significativamente, il pricing 1:1 potrebbe essere scorretto.

**Analisi**: Il pricing funziona cosi':
1. Intermediate vault chiede a CollateralVault: `balanceOf(cv_address)` -> ritorna N (in eToken units)
2. Poi: `convertToAssets(N)` -> ritorna N (1:1)
3. EulerRouter risolve: CollateralVault e' resolvedVault -> underlying = eToken
4. Poi risolve eToken come resolvedVault -> underlying = WETH
5. Applica conversione tramite eToken.convertToAssets e poi prezzo Chainlink

Quindi il pricing EFFETTIVAMENTE tiene conto dell'exchange rate dell'eToken nella catena di risoluzione dell'oracolo. Il 1:1 di CollateralVault non e' il pricing finale - e' solo un passaggio nella catena.

**Da verificare**:
- [ ] Confermare che la catena di risoluzione EulerRouter funziona come descritto sopra
- [ ] Verificare che non ci sia doppio conteggio o mancato conteggio dell'exchange rate
- [ ] Testare con exchange rate diversi da 1:1

**Impatto potenziale**: CRITICAL se il pricing e' sbagliato, ma probabilmente sicuro

---

### B-08: [ESPLORARE] rebalance() Come MEV Extraction

**Ipotesi**: `rebalance()` e' callable da chiunque (`callThroughEVC`). Ripaga credito in eccesso all'intermediate vault. Un attaccante MEV potrebbe sfruttare il timing del rebalance.

**Analisi**: rebalance ripaga eccesso, rendendo la posizione piu' conservativa. Non estrae valore direttamente. MA:
- Il repay riduce il debito dell'intermediate vault
- Questo riduce l'utilization rate
- Questo riduce il tasso di interesse per tutti i borrower
- Un attaccante potrebbe: (1) rebalance molti vault, (2) ridurre i tassi, (3) borroware a tassi bassi, (4) i tassi risalgono quando i vault si ri-bilanciano

**Da verificare**:
- [ ] Il beneficio di questo attacco e' significativo?
- [ ] C'e' un costo per l'attaccante (gas)?
- [ ] Probabilmente rientra in "liquidity-related impacts" (OUT OF SCOPE)

**Impatto potenziale**: LOW - Probabilmente out of scope come impatto di liquidita'

---

## SEZIONE C: Priorita' di Esplorazione

| Priorita' | ID | Titolo | Probabilita' In-Scope | Probabilita' Vulnerabile |
|-----------|-----|--------|----------------------|------------------------|
| 1 | B-01 | Flash Loan Exchange Rate Manipulation | ALTA | MEDIA |
| 2 | B-04 | Teleport toDeposit=0 toBorrow>0 | ALTA | MEDIA |
| 3 | B-03 | handleExternalLiquidation Reward | ALTA | BASSA-MEDIA |
| 4 | B-06 | Operator swapData Arbitrary Call | ALTA | BASSA |
| 5 | B-07 | convertToAssets 1:1 Pricing | ALTA | BASSA |
| 6 | F-01 | Permanent Freeze Oracle=0 | BORDERLINE | GIA' CONFERMATO |
| 7 | B-02 | EVC Batch Flash Loan | MEDIA | BASSA |
| 8 | B-05 | balanceOf Interest Accrual | MEDIA | BASSA |
| 9 | B-08 | rebalance MEV | BASSA (out scope) | BASSA |

---

## SEZIONE D: Come Procedere

Per ogni vettore in Sezione B, serve:
1. **PoC Foundry** che dimostri l'exploit (obbligatorio per Immunefi)
2. **Calcolo dell'impatto economico** (necessario per determinare reward)
3. **Verifica che non rientri nelle esclusioni** (oracle data, liquidity, centralization)

### Prossimi passi raccomandati:
1. Inizializzare il submodule `euler-price-oracle` per analizzare il meccanismo resolvedVault
2. Scrivere PoC per B-01 (flash loan exchange rate) - il piu' promettente
3. Scrivere PoC per B-04 (teleport exploit) - verifica rapida
4. Analizzare il contratto Euler Swapper on-chain per B-06
5. Se F-01 e' argomentabile come in-scope, scrivere un PoC formale con write-up convincente
