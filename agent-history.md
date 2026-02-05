# Agent history

This document is the **run log for AI agents**. **Each new agent run must append this file** with a dated entry describing what was done (features, fixes, decisions, troubleshooting). Do not remove or overwrite past entries.

The old shared-memory file is `WSL/docs/AGENT_WORKFLOW.md`; it is kept only in the WSL directory and is **not updated** anymore. From now on, **agent-history.md** is the document to update each run.

---

## Purpose

Keep a log of the history of features added and troubleshooting steps taken so future agents and maintainers have context.

---

## 2025-02-04 — Replace placeholders; agent-history as run log

**Goal:** Remove all placeholders from the repo and establish agent-history.md as the single agent run log.

**Done:**

1. **native-linux CUDA keygen**
   - Replaced placeholder `native-linux/cuda/keygen_secp256k1.cu` with the full implementation from native-win: secp256k1 field ops, point add/double, scalar multiplication, and `batch_keygen` writing 33-byte compressed pubkeys and 32-byte privkeys.

2. **Python keygen wired to CUDA kernel**
   - In both `native-win/keygen_1660.py` and `native-linux/keygen_1660.py`, replaced the “kernel not yet implemented” fallback with a real `_producer_cuda` that:
     - Allocates GPU and pagelocked host buffers for pubkeys (33 bytes) and privkeys (32 bytes).
     - Launches `batch_keygen(start_priv_lo, start_priv_hi, count, d_pub, d_priv)` with a 128-bit start key and correct carry when advancing.
     - Builds batches of `(private_key_int, public_key_bytes)` and puts them on the queue.
   - Added `import numpy as np` for kernel arguments.

3. **Docs**
   - Updated `native-linux/docs/AGENT_WORKFLOW.md` to state that GPU key generation is implemented via the CUDA kernel (with coincurve fallback). *(Note: that file was later removed; see below.)*

4. **AGENT_WORKFLOW.md scope**
   - `docs/AGENT_WORKFLOW.md` (the old agent workflow doc) is **only** in `WSL/docs/AGENT_WORKFLOW.md` and is not updated anymore. Removed from `native-linux/docs/` and `native-win/docs/`.

5. **agent-history.md**
   - This file was expanded with the above and with instructions that each new agent must **append** it with details of their run. `agent-history.md` is now the document to update each run.

**Placeholders:** Grep confirmed no remaining “placeholder” strings in the repo after these edits.

---

## 2025-02-04 — Agent-history setup

**Goal:** Make agent-history.md the single run log and ensure future agents append it.

**Done:**

1. **agent-history.md**
   - Added header stating that each new agent run must append this file with a dated entry.
   - Clarified that `WSL/docs/AGENT_WORKFLOW.md` is the old file, lives only in WSL, and is not updated; agent-history.md is the document to update each run.
   - Merged the earlier 2025-02-04 entry (placeholder removal, keygen wiring) into the same file.

2. **AGENT_WORKFLOW.md only in WSL**
   - Removed `native-linux/docs/AGENT_WORKFLOW.md` and `native-win/docs/AGENT_WORKFLOW.md` so AGENT_WORKFLOW.md exists only under `WSL/docs/`.

3. **Cursor rule**
   - Created `.cursor/rules/agent-history.mdc` (always apply) so every agent run is instructed to append agent-history.md at the end of the task with a dated summary of what was done, decisions, and troubleshooting.
