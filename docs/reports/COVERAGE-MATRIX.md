# Coverage matrix: the active records in the pinned AVE corpus

Generated. Do not edit by hand: change the scripts or regenerate (see the end). Read only: no rule is added or changed by this document. Every number below is printed by the scripts; none is typed. A rule count sits in a `count` marker because the scripts write it.

**Corpus sha256:** `7d3284314f7ea19af096df2b20e9d715b628a398cf88391d97be90a1ae074e74`. This is the file the README pins (the `counts:corpus` ref in README.md). It holds 89 records: 85 active and 4 not active (AVE-2026-00052 (rejected, layer content), AVE-2026-00053 (rejected, layer content), AVE-2026-00060 (rejected, layer transport), AVE-2026-00061 (rejected, layer content)). Only active records are in the matrix.

**Scanner:** commit `0ddf5603911711ab9103a0470c17e7cedb91a13b`. Example run engines: pattern, semgrep, yara. Rule files read: <!-- count:pattern_rules -->40<!-- /count --> pattern rules, <!-- count:yara_rules -->39<!-- /count --> YARA rules, <!-- count:semgrep_rules -->41<!-- /count --> Semgrep rules, the Magika engine, and the sandbox engine's record ids. Rules that cite an id the corpus does not publish: 0.

## Summary

| Group | Records |
|---|---|
| A. A file scanner can see the evidence, no rule cites the record | 10 |
| B. A file scanner can see the evidence, a rule cites the record | 33 |
| C. Runtime-stage, a static rule cites the record | 9 |
| D. Runtime-stage, no rule | 19 |
| E. Out of scope: layer `registry_metadata` | 14 (a rule cites 1 of them) |
| Total active | 85 |

- Groups A and B together are the 43 records whose layer is `content` or `server_card` and whose stage is `static_detection`.
- In group B, <!-- count:group_b_rules_without_a_test -->5<!-- /count --> rules have no test that runs a scan and names the rule or the record. In group C, 6 have none.
- 40 active records have no `example_patterns` (AVE-2026-00001 to AVE-2026-00040), so their rules cannot be checked against the record's own examples.
- Of the 110 `example_patterns` in the 32 records that have them and are not out of scope, the current static rules flag 10 with the record's own rule, 21 only with another record's rule, and 79 not at all.

## How to read the columns

- **Layer / stage / component:** the record's own fields, copied.
- **Can see:** a rule of the script, from layer and stage only. `content` or `server_card` with stage `static_detection` is evidence in a file (groups A and B). Stage `runtime_observed` or `runtime_drift_detected` is evidence that exists only while something runs (groups C and D). `registry_metadata` is registry data, not file content, and is out of scope for a file scanner (group E). This says nothing about whether a rule works.
- **Rules:** every rule in the rule files whose `ave_id` is this record. "Cites" is not "detects". X is the sandbox engine, which needs Docker and is off by default, listed only where it names the record.
- **Tests:** three counts. By rule id: test functions whose source runs a scan and names one of the record's rule ids. By record id only: tests that run a scan and name the AVE id but no rule id. Negative-named: of those, tests whose function name suggests a negative case (a name-based guess). `golden` means the golden fixture names the record or its rule. Tests that name an id without running a scan (a range formatter, for example) are not counted. A count above zero shows where to look. It does not show the test asserts a detection.
- **example_patterns:** the number of examples the record carries. Where it was run: how many the current static rules flag with the record's own rule (own), only with another record's rule (other), or not at all (none). Each example was written as one line of a SKILL.md and scanned with the pattern, YARA and Semgrep engines. LLM and sandbox stages were off. A rule might flag an example in a different file type or with more context.
- **Gap:** derived from the columns, in a fixed order. It is not a judgement about the record.

## A. A file scanner can see the evidence, no rule cites the record (10)

| Record | Title | Layer / stage / component | Rules (P pattern, Y YARA, S Semgrep, M Magika) | Tests: by rule id / by record id only / negative-named | example_patterns | Gap |
|---|---|---|---|---|---|---|
| AVE-2026-00041 | Prompt injection via MCP server-card tool descriptions be... | server_card / static_detection / mcp_server | none | 0 / 0 / 0 | 4: 0 own, 3 other, 1 none | no rule |
| AVE-2026-00045 | Privilege escalation via cross-app-access - pivot from lo... | content / static_detection / skill | none | 0 / 0 / 0 | 4: 0 own, 0 other, 4 none | no rule |
| AVE-2026-00049 | HTTP Host Header Injection via Agent-Initiated Request (B... | content / static_detection / mcp_server | none | 0 / 0 / 0 | 5: 0 own, 0 other, 5 none | no rule |
| AVE-2026-00057 | Obfuscated or encoded skill payload designed to evade sta... | content / static_detection / skill | none | 0 / 0 / 0 | 4: 0 own, 1 other, 3 none | no rule |
| AVE-2026-00059 | Fragmented cross-description prompt injection reassembled... | server_card / static_detection / mcp_server | none | 0 / 0 / 0 | 4: 0 own, 0 other, 4 none | no rule |
| AVE-2026-00065 | A2A agent card poisoning via embedded adversarial instruc... | server_card / static_detection / agent | none | 0 / 0 / 0 | 2: 0 own, 1 other, 1 none | no rule |
| AVE-2026-00069 | Multimodal image-hidden instructions (SkillCamo) bundled ... | content / static_detection / skill | none | 0 / 0 / 0 | 2: 0 own, 1 other, 1 none | no rule |
| AVE-2026-00074 | Reclaimable dead external anchor (GitHub owner, package, ... | content / static_detection / skill | none | 0 / 0 / 0 | 4: 0 own, 0 other, 4 none | no rule |
| AVE-2026-00075 | Bytecode poisoning: compiled .pyc cache diverges from its... | content / static_detection / skill | none | 0 / 0 / 0 | 3: 0 own, 0 other, 3 none | no rule |
| AVE-2026-00085 | Collusive cross-skill composition: a malicious workflow s... | content / static_detection / none | none | 0 / 0 / 0 | 3: 0 own, 0 other, 3 none | no rule |

## B. A file scanner can see the evidence, a rule cites the record (33)

| Record | Title | Layer / stage / component | Rules (P pattern, Y YARA, S Semgrep, M Magika) | Tests: by rule id / by record id only / negative-named | example_patterns | Gap |
|---|---|---|---|---|---|---|
| AVE-2026-00001 | Metamorphic payload via external config fetch | content / static_detection / skill | P bawbel-external-fetch; Y AVE_MetamorphicPayload_ExternalFetch; S ave-metamorphic-payload-url-fetch; X sandbox-* | 22 / 20 / 13, golden | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00002 | MCP tool description behavioral injection | content / static_detection / mcp_server | P bawbel-mcp-tool-poisoning; Y AVE_ShadowPermission_Override; S ave-mcp-tool-poisoning | 1 / 0 / 0, golden | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00003 | Credential exfiltration via agent instruction | content / static_detection / skill | P bawbel-env-exfiltration; Y AVE_DataExfiltration_Pattern; S ave-hardcoded-secret-in-skill; S ave-env-exfiltration; X sandbox-* | 2 / 0 / 0, golden | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00004 | Arbitrary code execution via shell pipe injection in agen... | content / static_detection / skill | P bawbel-shell-pipe; Y AVE_ShellPipeInjection; S ave-shell-injection-pattern; S ave-shell-pipe-injection; X sandbox-* | 3 / 0 / 0 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00005 | Recursive file system destruction via destructive command... | content / static_detection / skill | P bawbel-destructive-command; Y AVE_DestructiveCommand; S ave-rm-rf-pattern; S ave-destructive-command; X sandbox-* | 1 / 0 / 0 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00006 | Cryptocurrency wallet drain via malicious fund transfer i... | content / static_detection / skill | P bawbel-crypto-drain; Y AVE_CryptoDrain; S ave-crypto-drain | 1 / 0 / 0 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00007 | Agent goal hijack via direct instruction override in agen... | content / static_detection / skill | P bawbel-goal-override; Y AVE_GoalOverride; S ave-goal-override | 11 / 5 / 6, golden | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00008 | Agent persistence via self-replication instruction in age... | content / static_detection / skill | P bawbel-persistence-attempt; Y AVE_Persistence; S ave-persistence-attempt; X sandbox-* | 1 / 0 / 0 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00009 | AI identity jailbreak via role-play or persona override i... | content / static_detection / skill | P bawbel-jailbreak-instruction; Y AVE_IdentityJailbreak; S ave-jailbreak-instruction | 3 / 0 / 1 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00010 | Covert instruction concealment via secrecy directive in a... | content / static_detection / skill | P bawbel-hidden-instruction; Y AVE_HiddenInstruction; S ave-base64-encoded-payload; S ave-hidden-instruction | 1 / 0 / 0, golden | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00011 | Arbitrary tool invocation via dynamic tool call injection... | content / static_detection / skill | P bawbel-dynamic-tool-call; Y AVE_DynamicToolCall; S ave-dynamic-tool-call | 1 / 0 / 0 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00012 | Capability escalation via false permission grant in agent... | content / static_detection / skill | P bawbel-permission-escalation; Y AVE_PermissionEscalation; S ave-permission-escalation | 2 / 0 / 0 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00013 | Personal data exfiltration via PII collection and transmi... | content / static_detection / skill | P bawbel-pii-exfiltration; Y AVE_PIIExfiltration; S ave-pii-exfiltration | 1 / 0 / 0 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00014 | False authority claim via trust escalation impersonation ... | content / static_detection / skill | P bawbel-trust-escalation; Y AVE_TrustEscalation; S ave-trust-escalation | 1 / 0 / 0 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00015 | System prompt extraction via direct interrogation instruc... | content / static_detection / skill | P bawbel-system-prompt-leak; Y AVE_SystemPromptLeak; S ave-system-prompt-leak | 1 / 0 / 0 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00021 | Autonomous Action Without User Confirmation | content / static_detection / skill | P bawbel-autonomous-action; Y AVE_AutonomousAction; S ave-autonomous-action | 0 / 0 / 0 | 0 | no test that runs a scan names the rule or the record |
| AVE-2026-00022 | Scope Creep - Accessing Undeclared Resources | content / static_detection / skill | P bawbel-scope-creep; Y AVE_ScopeCreep; S ave-scope-creep | 0 / 0 / 0 | 0 | no test that runs a scan names the rule or the record |
| AVE-2026-00024 | Supply Chain - Content Type Mismatch (Magika) | content / static_detection / mcp_server | M bawbel-content-type-dangerous; M bawbel-content-type-mismatch | 1 / 0 / 0 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00025 | Conversation History Injection | content / static_detection / skill | P bawbel-history-injection; Y AVE_HistoryInjection; S ave-history-injection | 0 / 0 / 0 | 0 | no test that runs a scan names the rule or the record |
| AVE-2026-00026 | Exfiltration via Tool Output Encoding | content / static_detection / mcp_server | P bawbel-tool-output-exfil; Y AVE_ToolOutputExfil; S ave-tool-output-exfil | 3 / 0 / 1, golden | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00027 | Multi-Turn Attack - Instruction Persistence Across Conver... | content / static_detection / skill | P bawbel-multiturn-attack; Y AVE_MultiTurnAttack; S ave-multiturn-attack | 3 / 0 / 1 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00029 | Homoglyph or Unicode Obfuscation Attack | content / static_detection / skill | Y AVE_HomoglyphAttack | 0 / 0 / 0 | 0 | no test that runs a scan names the rule or the record |
| AVE-2026-00030 | Privilege Escalation via False Role Claim | content / static_detection / skill | P bawbel-role-claim-escalation; Y AVE_RoleClaimEscalation; S ave-role-claim-escalation | 3 / 0 / 1 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00032 | Network Reconnaissance Instruction | content / static_detection / skill | P bawbel-network-recon; Y AVE_NetworkRecon; S ave-network-recon | 3 / 0 / 1 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00033 | Unsafe Deserialization or Eval Instruction | content / static_detection / skill | P bawbel-unsafe-deserialization; Y AVE_UnsafeDeserialization; S ave-unsafe-deserialization | 4 / 0 / 1 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00034 | Supply Chain - Dynamic Third-Party Skill Import | content / static_detection / skill | P bawbel-supply-chain-skill; Y AVE_SupplyChainSkill; S ave-supply-chain-skill | 3 / 0 / 1 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00036 | Lateral Movement - Pivot to Other Systems | content / static_detection / skill | P bawbel-lateral-movement; Y AVE_LateralMovement; S ave-lateral-movement | 3 / 0 / 1 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00038 | Excessive Agency - Unbounded Tool Use or Sub-Agent Spawning | content / static_detection / skill | P bawbel-excessive-agency; Y AVE_ExcessiveAgency; S ave-excessive-agency | 4 / 0 / 1 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00039 | Covert Channel - Steganographic Data Exfiltration | content / static_detection / skill | P bawbel-covert-channel; Y AVE_CovertChannel; S ave-covert-channel | 4 / 0 / 1 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00040 | Insecure Output - Unescaped Injection into Downstream System | content / static_detection / mcp_server | P bawbel-unsafe-output; Y AVE_UnsafeOutput; S ave-unsafe-output | 4 / 0 / 1 | 0 | none found; the record has no example_patterns to check the rule against |
| AVE-2026-00046 | MCP tool hook hijacking - redirect tool execution to atta... | server_card / static_detection / skill | P bawbel-hook-hijack | 0 / 0 / 0 | 5: 5 own, 0 other, 0 none | no test that runs a scan names the rule or the record |
| AVE-2026-00047 | Hardcoded credentials in agent component - API keys and s... | content / static_detection / skill | P bawbel-hardcoded-credential | 0 / 8 / 3, golden | 5: 5 own, 0 other, 0 none | tests name the record only, not a rule id |
| AVE-2026-00048 | Unsafe agent delegation chain - sub-agent spawned with in... | content / static_detection / skill | P bawbel-unsafe-delegation | 0 / 6 / 2 | 5: 0 own, 4 other, 1 none | tests name the record only, not a rule id; 5 of 5 example_patterns not flagged by its own rule |

## C. Runtime-stage records that a static rule cites (9)

| Record | Title | Layer / stage / component | Rules (P pattern, Y YARA, S Semgrep, M Magika) | Tests: by rule id / by record id only / negative-named | example_patterns | Gap |
|---|---|---|---|---|---|---|
| AVE-2026-00016 | Indirect Prompt Injection via RAG Retrieval | runtime / runtime_observed / other | P bawbel-rag-injection; Y AVE_RAGInjection; S ave-rag-injection | 0 / 0 / 0 | 0 | static rule cites a runtime-stage record, it sees only the text form; no test names the rule |
| AVE-2026-00018 | Tool Result Manipulation or Output Poisoning | runtime / runtime_observed / mcp_server | P bawbel-tool-result-manipulation; Y AVE_ToolResultManipulation; S ave-tool-result-manipulation | 0 / 0 / 0 | 0 | static rule cites a runtime-stage record, it sees only the text form; no test names the rule |
| AVE-2026-00019 | Agent Memory Poisoning | runtime / runtime_observed / skill | P bawbel-memory-poisoning; Y AVE_MemoryPoisoning; S ave-memory-poisoning | 0 / 0 / 0 | 0 | static rule cites a runtime-stage record, it sees only the text form; no test names the rule |
| AVE-2026-00020 | Cross-Agent Prompt Injection (A2A) | runtime / runtime_observed / skill | P bawbel-a2a-injection; Y AVE_A2AInjection; S ave-a2a-injection | 0 / 0 / 0 | 0 | static rule cites a runtime-stage record, it sees only the text form; no test names the rule |
| AVE-2026-00023 | Model Context Window Manipulation | runtime / runtime_observed / mcp_server | P bawbel-context-manipulation; Y AVE_ContextManipulation; S ave-context-manipulation | 0 / 0 / 0 | 0 | static rule cites a runtime-stage record, it sees only the text form; no test names the rule |
| AVE-2026-00028 | Prompt Injection via File or Document Content | runtime / runtime_observed / skill | P bawbel-file-prompt-injection; Y AVE_FilePromptInjection; S ave-file-prompt-injection | 3 / 0 / 1 | 0 | static rule cites a runtime-stage record, it sees only the text form; tested |
| AVE-2026-00031 | Training Data or Feedback Loop Poisoning | runtime / runtime_observed / skill | P bawbel-feedback-poisoning; Y AVE_FeedbackPoisoning; S ave-feedback-poisoning | 3 / 0 / 1 | 0 | static rule cites a runtime-stage record, it sees only the text form; tested |
| AVE-2026-00035 | Environment or Sensor Data Manipulation | runtime / runtime_observed / skill | Y AVE_EnvManipulation | 0 / 0 / 0 | 0 | static rule cites a runtime-stage record, it sees only the text form; no test names the rule |
| AVE-2026-00037 | Prompt Injection via Image or Vision Input | runtime / runtime_observed / skill | P bawbel-vision-prompt-injection; Y AVE_VisionPromptInjection; S ave-vision-prompt-injection | 3 / 0 / 1 | 0 | static rule cites a runtime-stage record, it sees only the text form; tested |

## D. Runtime-stage records no rule cites (19)

| Record | Title | Layer / stage / component | Rules (P pattern, Y YARA, S Semgrep, M Magika) | Tests: by rule id / by record id only / negative-named | example_patterns | Gap |
|---|---|---|---|---|---|---|
| AVE-2026-00042 | Payload injection into agent-generated orchestration code... | runtime / runtime_observed / skill | none | 0 / 0 / 0 | 4: 0 own, 1 other, 3 none | no rule; evidence appears only at runtime |
| AVE-2026-00043 | Prompt injection via rich UI payload (canvas, artifact, f... | runtime / runtime_observed / mcp_server | none | 0 / 0 / 0 | 4: 0 own, 4 other, 0 none | no rule; evidence appears only at runtime |
| AVE-2026-00044 | Prompt injection via poisoned async task result injected ... | runtime / runtime_observed / skill | none | 0 / 0 / 0 | 5: 0 own, 1 other, 4 none | no rule; evidence appears only at runtime |
| AVE-2026-00050 | Parasitic Toolchain - Silent Tool Registration and Persis... | runtime / runtime_observed / mcp_server | none | 0 / 0 / 0 | 5: 0 own, 2 other, 3 none | no rule; evidence appears only at runtime |
| AVE-2026-00054 | Code-execution sandbox escape via JavaScript prototype-ch... | runtime / runtime_observed / tool | none | 0 / 0 / 0 | 3: 0 own, 0 other, 3 none | no rule; evidence appears only at runtime |
| AVE-2026-00056 | Zero-click data exfiltration via markdown image auto-fetc... | runtime / runtime_observed / agent | none | 0 / 0 / 0 | 3: 0 own, 0 other, 3 none | no rule; evidence appears only at runtime |
| AVE-2026-00066 | Hallucinated skill-name squatting (HalluSquatting) | runtime / runtime_observed / skill | none | 0 / 0 / 0 | 2: 0 own, 0 other, 2 none | no rule; evidence appears only at runtime |
| AVE-2026-00067 | Skill composition trust transfer: an upstream skill's out... | runtime / runtime_observed / skill | none | 0 / 0 / 0 | 2: 0 own, 0 other, 2 none | no rule; evidence appears only at runtime |
| AVE-2026-00068 | CLI command composition risk: benign commands compose thr... | runtime / runtime_observed / skill | none | 0 / 0 / 0 | 2: 0 own, 0 other, 2 none | no rule; evidence appears only at runtime |
| AVE-2026-00070 | Distributed cross-agent backdoor fragments reassembled ex... | runtime / runtime_drift_detected / agent | none | 0 / 0 / 0 | 2: 0 own, 1 other, 1 none | no rule; evidence appears only at runtime |
| AVE-2026-00078 | Consensus poisoning: orchestrator accepts a single sub-ag... | runtime / runtime_observed / agent | none | 0 / 0 / 0 | 3: 0 own, 1 other, 2 none | no rule; evidence appears only at runtime |
| AVE-2026-00079 | Plan hijacking via false completion signal: forced early ... | runtime / runtime_drift_detected / agent | none | 0 / 0 / 0 | 3: 0 own, 0 other, 3 none | no rule; evidence appears only at runtime |
| AVE-2026-00080 | Silent agent substitution: unverified process at a routin... | runtime / runtime_observed / agent | none | 0 / 0 / 0 | 3: 0 own, 0 other, 3 none | no rule; evidence appears only at runtime |
| AVE-2026-00081 | Lingering authority: a task-scoped capability outlives th... | runtime / runtime_observed / none | none | 0 / 0 / 0 | 3: 0 own, 0 other, 3 none | no rule; evidence appears only at runtime |
| AVE-2026-00083 | Silent guardrail comparison failure: a protection mechani... | runtime / runtime_observed / none | none | 0 / 0 / 0 | 3: 0 own, 0 other, 3 none | no rule; evidence appears only at runtime |
| AVE-2026-00086 | Mid-session WebMCP tool hijacking: a live registry swap r... | runtime / runtime_observed / none | none | 0 / 0 / 0 | 3: 0 own, 0 other, 3 none | no rule; evidence appears only at runtime |
| AVE-2026-00087 | Agentjacking: a crafted tool response visually mimics a t... | runtime / runtime_observed / none | none | 0 / 0 / 0 | 3: 0 own, 0 other, 3 none | no rule; evidence appears only at runtime |
| AVE-2026-00088 | Sandbox side-effect trust handoff: an agent-written works... | runtime / runtime_observed / agent | none | 0 / 0 / 0 | 4: 0 own, 0 other, 4 none | no rule; evidence appears only at runtime |
| AVE-2026-00089 | Model-supplied sandbox boundary: a tool parameter the mod... | runtime / runtime_observed / agent | none | 0 / 0 / 0 | 3: 0 own, 1 other, 2 none | no rule; evidence appears only at runtime |

## E. Out of scope: layer registry_metadata (14)

| Record | Title | Layer / stage / component | Rules (P pattern, Y YARA, S Semgrep, M Magika) | Tests: by rule id / by record id only / negative-named | example_patterns | Gap |
|---|---|---|---|---|---|---|
| AVE-2026-00017 | MCP Server Impersonation or Spoofing | registry_metadata / static_detection / mcp_server | P bawbel-mcp-impersonation; Y AVE_MCPImpersonation; S ave-mcp-impersonation | 0 / 0 / 0 | 0 | out of scope for a file scanner |
| AVE-2026-00051 | OAuth Discovery Rebinding - Authorization Endpoint Redire... | registry_metadata / static_detection / mcp_server | none | 0 / 0 / 0 | 5 (not run) | out of scope for a file scanner |
| AVE-2026-00055 | Command execution via untrusted MCP server launch configu... | registry_metadata / static_detection / mcp_server | none | 0 / 0 / 0 | 3 (not run) | out of scope for a file scanner |
| AVE-2026-00058 | Deceptive skill trigger or activation-scope manipulation ... | registry_metadata / static_detection / skill | none | 0 / 0 / 0 | 3 (not run) | out of scope for a file scanner |
| AVE-2026-00062 | Unpinned dependency version allowing supply chain substit... | registry_metadata / static_detection / skill | none | 0 / 0 / 0 | 2 (not run) | out of scope for a file scanner |
| AVE-2026-00063 | Human approval gate bypassed via declarative configuratio... | registry_metadata / static_detection / skill | none | 0 / 0 / 0 | 2 (not run) | out of scope for a file scanner |
| AVE-2026-00064 | Zero-click code execution via project-load auto-run confi... | registry_metadata / static_detection / skill | none | 0 / 0 / 0 | 2 (not run) | out of scope for a file scanner |
| AVE-2026-00071 | MCP daemon redirect via DOCKER_HOST or host flag, contain... | registry_metadata / static_detection / skill | none | 0 / 0 / 0 | 2 (not run) | out of scope for a file scanner |
| AVE-2026-00072 | MCP server bound to all network interfaces with no authen... | registry_metadata / static_detection / mcp_server | none | 0 / 0 / 0 | 2 (not run) | out of scope for a file scanner |
| AVE-2026-00073 | Telemetry or API endpoint redirect via static configurati... | registry_metadata / static_detection / skill | none | 0 / 0 / 0 | 5 (not run) | out of scope for a file scanner |
| AVE-2026-00076 | Natural-language steering of an approval classifier subag... | registry_metadata / static_detection / agent | none | 0 / 0 / 0 | 3 (not run) | out of scope for a file scanner |
| AVE-2026-00077 | Cross-origin tool and resource declaration within a singl... | registry_metadata / static_detection / mcp_server | none | 0 / 0 / 0 | 3 (not run) | out of scope for a file scanner |
| AVE-2026-00082 | Local skill name collision: deterministic router shadowin... | registry_metadata / static_detection / skill | none | 0 / 0 / 0 | 2 (not run) | out of scope for a file scanner |
| AVE-2026-00084 | Lifecycle hook trust decoupling: a vetted plugin update s... | registry_metadata / static_detection / none | none | 0 / 0 / 0 | 3 (not run) | out of scope for a file scanner |

## Notes

- **Rules with no test that runs a scan and names them.** Group B: AVE-2026-00021, AVE-2026-00022, AVE-2026-00025, AVE-2026-00029, AVE-2026-00046. Group C: AVE-2026-00016, AVE-2026-00018, AVE-2026-00019, AVE-2026-00020, AVE-2026-00023, AVE-2026-00035.
- **Rules that do not flag their own record's examples.** Records that have a rule and examples where fewer than all examples are flagged by the record's own rule: AVE-2026-00048 (0 of 5).
- **Records in group A, by what the examples show.** AVE-2026-00041 (3 of 4 flagged by another record's rule), AVE-2026-00057 (1 of 4 flagged by another record's rule), AVE-2026-00065 (1 of 2 flagged by another record's rule), AVE-2026-00069 (1 of 2 flagged by another record's rule).
- **Display.** Titles are cut at 60 characters and an em dash in a title is shown as a hyphen. The corpus is not changed.

## What this does not show

- Whether a rule detects the attack its record describes. "Cites" means the rule's `ave_id` field names the record.
- Whether a test asserts a detection. A test counts when its source runs a scan and names the rule or the record.
- Anything about file types other than the one-line SKILL.md the examples were written into.
- Anything about the LLM or sandbox stages, which were off.

## Regenerate

```text
python3 -I scripts/coverage_matrix.py --corpus CORPUS.json --src . --out matrix.json
python3 scripts/coverage_examples.py matrix.json examples.json     # needs the pattern, YARA and Semgrep engines installed
python3 -I scripts/coverage_render.py matrix.json examples.json --scanner-ref "$(git rev-parse HEAD)" > docs/reports/COVERAGE-MATRIX.md
```

- `scripts/coverage_matrix.py`: reads the corpus file, the rule files and tests/ as text, writes the JSON.
- `scripts/coverage_examples.py`: scans each example with the static engines. Nothing is executed.
- `scripts/coverage_render.py`: prints this document.

