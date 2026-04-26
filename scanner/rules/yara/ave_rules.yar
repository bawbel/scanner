/*
 * Bawbel Scanner — YARA Rules v0.1.0
 * Detects known agentic AI vulnerability patterns
 * AVE Standard: github.com/bawbel/bawbel-ave
 */

rule AVE_MetamorphicPayload_ExternalFetch
{
    meta:
        ave_id      = "AVE-2026-00001"
        attack_class = "Metamorphic Payload"
        severity    = "CRITICAL"
        cvss_ai     = "9.4"
        description = "Skill fetches instructions from external URL at runtime"
        owasp       = "ASI01, ASI08"

    strings:
        // Fetch patterns in natural language instructions
        $fetch1 = "fetch(" nocase
        $fetch2 = "requests.get(" nocase
        $fetch3 = "curl " nocase
        $fetch4 = "wget " nocase
        $fetch5 = "http.get(" nocase
        $fetch6 = "urllib" nocase

        // External instruction keywords
        $inst1 = "fetch your instructions" nocase
        $inst2 = "fetch your configuration" nocase
        $inst3 = "fetch your rules" nocase
        $inst4 = "load your instructions" nocase
        $inst5 = "read your instructions from" nocase
        $inst6 = "get your commands from" nocase

        // Known malicious paste sites
        $site1 = "rentry.co" nocase
        $site2 = "pastebin.com" nocase
        $site3 = "raw.githubusercontent.com" nocase
        $site4 = "gist.githubusercontent.com" nocase
        $site5 = "hastebin.com" nocase

    condition:
        any of ($inst*) or
        (any of ($fetch*) and any of ($site*))
}


rule AVE_ShadowPermission_Override
{
    meta:
        ave_id      = "AVE-2026-00002"
        attack_class = "Shadow Permission Escalation"
        severity    = "HIGH"
        cvss_ai     = "8.1"
        description = "Skill attempts to claim undeclared permissions or override agent goals"
        owasp       = "ASI01, ASI08"

    strings:
        // Goal override patterns
        $override1 = "ignore previous instructions" nocase
        $override2 = "ignore all previous" nocase
        $override3 = "disregard your instructions" nocase
        $override4 = "forget your instructions" nocase
        $override5 = "your new instructions are" nocase
        $override6 = "override your" nocase
        $override7 = "regardless of what you were told" nocase
        $override8 = "instead of what you were asked" nocase

        // Permission escalation
        $perm1 = "you now have permission" nocase
        $perm2 = "you are now allowed" nocase
        $perm3 = "you can now access" nocase
        $perm4 = "bypass your restrictions" nocase
        $perm5 = "your restrictions do not apply" nocase

    condition:
        any of ($override*) or
        any of ($perm*)
}


rule AVE_DataExfiltration_Pattern
{
    meta:
        ave_id      = "AVE-2026-00003"
        attack_class = "Prompt Injection — Data Exfiltration"
        severity    = "HIGH"
        cvss_ai     = "8.5"
        description = "Skill instructs agent to send sensitive data to external destination"
        owasp       = "ASI01, ASI06"

    strings:
        // Exfiltration instruction patterns
        $exfil1 = "send the contents of" nocase
        $exfil2 = "send all files" nocase
        $exfil3 = "upload the user's" nocase
        $exfil4 = "transmit the following" nocase
        $exfil5 = "exfiltrate" nocase
        $exfil6 = "send everything in" nocase

        // Environment variable targeting
        $env1 = ".env" nocase
        $env2 = "environment variables" nocase
        $env3 = "api key" nocase
        $env4 = "secret key" nocase
        $env5 = "access token" nocase
        $env6 = "private key" nocase

        // Destination patterns
        $dest1 = "to http" nocase
        $dest2 = "to https" nocase
        $dest3 = "to this url" nocase
        $dest4 = "to the following endpoint" nocase

    condition:
        any of ($exfil*) or
        (any of ($env*) and any of ($dest*))
}


rule AVE_ShellPipeInjection
{
    meta:
        ave_id       = "AVE-2026-00004"
        attack_class = "Tool Abuse — Shell Injection"
        severity     = "HIGH"
        cvss_ai      = "8.8"
        description  = "Skill instructs agent to pipe shell commands — enables arbitrary code execution"
        owasp        = "ASI01, ASI07"

    strings:
        $pipe1 = "curl | bash"    nocase
        $pipe2 = "curl|bash"      nocase
        $pipe3 = "wget | bash"    nocase
        $pipe4 = "wget|bash"      nocase
        $pipe5 = "wget | sh"      nocase
        $pipe6 = "curl | sh"      nocase
        $pipe7 = "| python"       nocase
        $pipe8 = "| pip"          nocase
        $pipe9 = "| npm"          nocase
        $pipe10 = "eval $("       nocase

    condition:
        any of ($pipe*)
}


rule AVE_DestructiveCommand
{
    meta:
        ave_id       = "AVE-2026-00005"
        attack_class = "Tool Abuse — Destructive Command"
        severity     = "CRITICAL"
        cvss_ai      = "9.1"
        description  = "Skill instructs agent to delete files or directories recursively"
        owasp        = "ASI07"

    strings:
        $rm1 = "rm -rf /"        nocase
        $rm2 = "rm -rf ~"        nocase
        $rm3 = "rm -fr /"        nocase
        $rm4 = "rm -fr ~"        nocase
        $rm5 = "rmdir /s"        nocase
        $rm6 = "del /f /s /q"    nocase
        $rm7 = "format c:"       nocase
        $rm8 = ":(){:|:&};:"     // fork bomb

    condition:
        any of ($rm*)
}


rule AVE_CryptoDrain
{
    meta:
        ave_id       = "AVE-2026-00006"
        attack_class = "Cryptocurrency Drain"
        severity     = "CRITICAL"
        cvss_ai      = "9.6"
        description  = "Skill instructs agent to transfer cryptocurrency or access wallet keys"
        owasp        = "ASI01, ASI06"

    strings:
        $drain1 = "transfer all"           nocase
        $drain2 = "send all funds"         nocase
        $drain3 = "drain the wallet"       nocase
        $drain4 = "withdraw all"           nocase
        $drain5 = "private key"            nocase
        $drain6 = "seed phrase"            nocase
        $drain7 = "mnemonic phrase"        nocase
        $drain8 = "wallet.json"            nocase
        $drain9 = "keystore"               nocase

        $crypto1 = "bitcoin"               nocase
        $crypto2 = "ethereum"              nocase
        $crypto3 = "metamask"              nocase
        $crypto4 = "web3.eth"              nocase
        $crypto5 = "sendTransaction"       nocase

    condition:
        any of ($drain1, $drain2, $drain3, $drain4) or
        (any of ($drain5, $drain6, $drain7, $drain8, $drain9) and any of ($crypto*))
}


rule AVE_GoalOverride
{
    meta:
        ave_id       = "AVE-2026-00007"
        attack_class = "Goal Hijack"
        severity     = "HIGH"
        cvss_ai      = "8.1"
        description  = "Skill instructs agent to ignore or override its primary instructions"
        owasp        = "ASI01, ASI08"

    strings:
        $goal1 = "ignore previous instructions"     nocase
        $goal2 = "ignore all previous"              nocase
        $goal3 = "disregard your instructions"      nocase
        $goal4 = "forget your instructions"         nocase
        $goal5 = "your new instructions are"        nocase
        $goal6 = "override your instructions"       nocase
        $goal7 = "instead of what you were asked"   nocase
        $goal8 = "regardless of what you were told" nocase
        $goal9 = "your real task is"                nocase
        $goal10 = "your actual goal is"             nocase
        $goal11 = "disregard all previous"          nocase

    condition:
        any of ($goal*)
}


rule AVE_Persistence
{
    meta:
        ave_id       = "AVE-2026-00008"
        attack_class = "Persistence / Self-Replication"
        severity     = "HIGH"
        cvss_ai      = "8.4"
        description  = "Skill attempts to install itself, schedule tasks, or persist across sessions"
        owasp        = "ASI07"

    strings:
        $persist1 = "crontab"              nocase
        $persist2 = "cron job"             nocase
        $persist3 = "startup folder"       nocase
        $persist4 = "autostart"            nocase
        $persist5 = "~/.bashrc"            nocase
        $persist6 = "~/.zshrc"             nocase
        $persist7 = "~/.profile"           nocase
        $persist8 = "systemctl enable"     nocase
        $persist9 = "launchctl"            nocase
        $persist10 = "copy yourself"       nocase
        $persist11 = "replicate this skill" nocase
        $persist12 = "install this skill"  nocase
        $persist13 = "WindowsStartup"      nocase
        $persist14 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase

    condition:
        any of ($persist*)
}


rule AVE_IdentityJailbreak
{
    meta:
        ave_id       = "AVE-2026-00009"
        attack_class = "Prompt Injection — Jailbreak"
        severity     = "HIGH"
        cvss_ai      = "8.3"
        description  = "Skill attempts to override the agent's identity or disable safety guidelines"
        owasp        = "ASI01, ASI08"

    strings:
        $jb1  = "pretend you are"              nocase
        $jb2  = "act as if you are"            nocase
        $jb3  = "you are no longer"            nocase
        $jb4  = "DAN mode"                     nocase
        $jb5  = "developer mode enabled"       nocase
        $jb6  = "jailbreak mode"               nocase
        $jb7  = "ignore your safety"           nocase
        $jb8  = "bypass your safety"           nocase
        $jb9  = "without restrictions"         nocase
        $jb10 = "no content policy"            nocase
        $jb11 = "do anything now"              nocase
        $jb12 = "unrestricted AI"              nocase
        $jb13 = "forget you are an AI"         nocase
        $jb14 = "act as an AI without"         nocase

    condition:
        any of ($jb*)
}


rule AVE_HiddenInstruction
{
    meta:
        ave_id       = "AVE-2026-00010"
        attack_class = "Prompt Injection — Hidden Instruction"
        severity     = "HIGH"
        cvss_ai      = "7.9"
        description  = "Skill instructs agent to conceal its instructions from the user"
        owasp        = "ASI01, ASI09"

    strings:
        $hide1 = "do not tell the user"         nocase
        $hide2 = "do not inform the user"        nocase
        $hide3 = "never reveal"                  nocase
        $hide4 = "keep this secret"              nocase
        $hide5 = "keep this hidden"              nocase
        $hide6 = "do not acknowledge"            nocase
        $hide7 = "do not disclose"               nocase
        $hide8 = "deny having received"          nocase
        $hide9 = "must remain confidential"      nocase
        $hide10 = "do not mention these"         nocase
        $hide11 = "this message must not"        nocase

    condition:
        any of ($hide*)
}


rule AVE_DynamicToolCall
{
    meta:
        ave_id       = "AVE-2026-00011"
        attack_class = "Tool Abuse — Dynamic Tool Call"
        severity     = "HIGH"
        cvss_ai      = "8.2"
        description  = "Skill embeds explicit tool invocations with attacker-controlled parameters"
        owasp        = "ASI07"

    strings:
        $tool1 = "call this tool with"           nocase
        $tool2 = "execute the following tool"    nocase
        $tool3 = "invoke tool"                   nocase
        $tool4 = "call the tool"                 nocase
        $tool5 = "run the following tool"        nocase
        $tool6 = "execute tool:"                 nocase
        $tool7 = "tool_call"                     nocase
        $tool8 = "function_call"                 nocase

    condition:
        any of ($tool*)
}


rule AVE_PermissionEscalation
{
    meta:
        ave_id       = "AVE-2026-00012"
        attack_class = "Privilege Escalation — Permission Grant"
        severity     = "HIGH"
        cvss_ai      = "7.8"
        description  = "Skill falsely claims the agent has been granted elevated permissions"
        owasp        = "ASI01, ASI08"

    strings:
        $perm1 = "you now have permission"       nocase
        $perm2 = "you are now allowed to"        nocase
        $perm3 = "your restrictions have been"   nocase
        $perm4 = "you have been granted"         nocase
        $perm5 = "elevated access granted"       nocase
        $perm6 = "admin mode enabled"            nocase
        $perm7 = "sudo mode"                     nocase
        $perm8 = "unrestricted access"           nocase

    condition:
        any of ($perm*)
}


rule AVE_PIIExfiltration
{
    meta:
        ave_id       = "AVE-2026-00013"
        attack_class = "Data Exfiltration — PII Theft"
        severity     = "HIGH"
        cvss_ai      = "8.0"
        description  = "Skill instructs agent to collect and transmit personally identifiable information"
        owasp        = "ASI01, ASI06"

    strings:
        $pii1 = "collect the user's name"        nocase
        $pii2 = "collect email"                  nocase
        $pii3 = "collect phone"                  nocase
        $pii4 = "collect address"                nocase
        $pii5 = "gather personal information"    nocase
        $pii6 = "extract personal data"          nocase
        $pii7 = "credit card number"             nocase
        $pii8 = "social security"                nocase
        $pii9 = "passport number"                nocase
        $pii10 = "date of birth"                 nocase

        $send1 = "send to"                       nocase
        $send2 = "transmit to"                   nocase
        $send3 = "post to"                       nocase
        $send4 = "upload to"                     nocase

    condition:
        (any of ($pii1, $pii2, $pii3, $pii4, $pii5, $pii6) and any of ($send*)) or
        any of ($pii7, $pii8, $pii9, $pii10)
}


rule AVE_TrustEscalation
{
    meta:
        ave_id       = "AVE-2026-00014"
        attack_class = "Social Engineering — Trust Escalation"
        severity     = "MEDIUM"
        cvss_ai      = "6.5"
        description  = "Skill falsely claims to originate from a trusted AI provider or developer"
        owasp        = "ASI01, ASI08"

    strings:
        $trust1 = "this message is from Anthropic"  nocase
        $trust2 = "message from OpenAI"             nocase
        $trust3 = "message from Google"             nocase
        $trust4 = "message from Microsoft"          nocase
        $trust5 = "I am your developer"             nocase
        $trust6 = "I am your creator"               nocase
        $trust7 = "I am your operator"              nocase
        $trust8 = "sent by Anthropic"               nocase
        $trust9 = "official message from"           nocase
        $trust10 = "verified instruction from"      nocase

    condition:
        any of ($trust*)
}


rule AVE_SystemPromptLeak
{
    meta:
        ave_id       = "AVE-2026-00015"
        attack_class = "Information Disclosure — System Prompt Leak"
        severity     = "MEDIUM"
        cvss_ai      = "6.2"
        description  = "Skill instructs agent to reveal its system prompt or internal configuration"
        owasp        = "ASI01, ASI09"

    strings:
        $leak1 = "reveal your system prompt"     nocase
        $leak2 = "show your system prompt"       nocase
        $leak3 = "print your system prompt"      nocase
        $leak4 = "repeat your instructions"      nocase
        $leak5 = "output your instructions"      nocase
        $leak6 = "what are your exact instructions" nocase
        $leak7 = "display your guidelines"       nocase
        $leak8 = "show your configuration"       nocase
        $leak9 = "tell me your rules"            nocase
        $leak10 = "reveal your constraints"      nocase

    condition:
        any of ($leak*)
}

/*
 * Bawbel Scanner — YARA Rules v1.0.0 (AVE-2026-00026 to AVE-2026-00040)
 * New attack classes added in v1.0.0
 */

// AVE-2026-00026 — Tool output exfiltration
rule AVE_ToolOutputExfil
{
    meta:
        ave_id      = "AVE-2026-00026"
        title       = "Exfiltration via tool output encoding"
        severity    = "CRITICAL"
        cvss_ai     = "9.1"
    strings:
        $a = "encode" nocase
        $b = "base64" nocase
        $c = "exfiltrate" nocase
        $d = "smuggle" nocase
        $t1 = "api_key" nocase
        $t2 = "password" nocase
        $t3 = "secret" nocase
        $t4 = "credential" nocase
    condition:
        (($a or $b) and ($t1 or $t2 or $t3 or $t4)) or ($c and ($t1 or $t2 or $t3 or $t4)) or $d
}

// AVE-2026-00027 — Multi-turn attack persistence
rule AVE_MultiTurnAttack
{
    meta:
        ave_id   = "AVE-2026-00027"
        title    = "Multi-turn attack — persist instructions across turns"
        severity = "HIGH"
        cvss_ai  = "8.4"
    strings:
        $a = "retain" nocase wide ascii
        $b = "remember these instructions" nocase
        $c = "regardless of memory" nocase
        $d = "across all future" nocase
        $e = "survive context" nocase
        $f = "memory reset" nocase
        $g = "re-apply instructions" nocase
    condition:
        any of them
}

// AVE-2026-00028 — File prompt injection
rule AVE_FilePromptInjection
{
    meta:
        ave_id   = "AVE-2026-00028"
        title    = "Prompt injection via file or document content"
        severity = "HIGH"
        cvss_ai  = "8.3"
    strings:
        $a = "execute instructions found in the file" nocase
        $b = "follow instructions in the document" nocase
        $c = "treat file content as instructions" nocase
        $d = "treat document content as instructions" nocase
        $e = "obey instructions in attachment" nocase
        $f = "instructions embedded in" nocase
    condition:
        any of them
}

// AVE-2026-00030 — Role claim privilege escalation
rule AVE_RoleClaimEscalation
{
    meta:
        ave_id   = "AVE-2026-00030"
        title    = "Privilege escalation via false role claim"
        severity = "CRITICAL"
        cvss_ai  = "9.0"
    strings:
        $a = "if the user claims to be admin" nocase
        $b = "if user says they are root" nocase
        $c = "grant admin access if" nocase
        $d = "trust all claims of identity" nocase
        $e = "bypass authentication if" nocase
        $f = "bypass authorization if" nocase
        $g = "accept any role claim" nocase
    condition:
        any of them
}

// AVE-2026-00031 — Feedback loop poisoning
rule AVE_FeedbackPoisoning
{
    meta:
        ave_id   = "AVE-2026-00031"
        title    = "Training data or feedback loop poisoning"
        severity = "HIGH"
        cvss_ai  = "8.6"
    strings:
        $a = "poison the training" nocase
        $b = "corrupt the feedback" nocase
        $c = "manipulate reward" nocase
        $d = "bias the training data" nocase
        $e = "rate this response as good regardless" nocase
        $f = "inject into training data" nocase
        $g = "rlhf" nocase
    condition:
        any of them
}

// AVE-2026-00032 — Network reconnaissance
rule AVE_NetworkRecon
{
    meta:
        ave_id   = "AVE-2026-00032"
        title    = "Network reconnaissance instruction"
        severity = "HIGH"
        cvss_ai  = "8.2"
    strings:
        $a = "nmap" nocase
        $b = "port scan" nocase
        $c = "network scan" nocase
        $d = "host discovery" nocase
        $e = "service enumeration" nocase
        $f = "scan internal network" nocase
        $g = "enumerate open ports" nocase
        $h = "probe subnet" nocase
    condition:
        any of them
}

// AVE-2026-00033 — Unsafe deserialization
rule AVE_UnsafeDeserialization
{
    meta:
        ave_id   = "AVE-2026-00033"
        title    = "Unsafe deserialization or eval instruction"
        severity = "CRITICAL"
        cvss_ai  = "9.3"
    strings:
        $a = "eval(input" nocase
        $b = "exec(input" nocase
        $c = "execute the code received" nocase
        $d = "deserialize untrusted" nocase
        $e = "unpickle" nocase
        $f = "yaml.load(" nocase
        $g = "execute untrusted code" nocase
        $h = "run arbitrary" nocase
    condition:
        any of them
}

// AVE-2026-00034 — Supply chain skill import
rule AVE_SupplyChainSkill
{
    meta:
        ave_id   = "AVE-2026-00034"
        title    = "Supply chain — dynamic third-party skill import"
        severity = "CRITICAL"
        cvss_ai  = "9.2"
    strings:
        $a = "load skill from http" nocase
        $b = "import plugin from" nocase
        $c = "install skill from" nocase
        $d = "fetch tool from external" nocase
        $e = "dynamically load" nocase
        $f = "runtime import" nocase
        $g = "download and install" nocase
    condition:
        any of them
}

// AVE-2026-00036 — Lateral movement
rule AVE_LateralMovement
{
    meta:
        ave_id   = "AVE-2026-00036"
        title    = "Lateral movement — pivot to other systems"
        severity = "CRITICAL"
        cvss_ai  = "9.4"
    strings:
        $a = "pivot to other system" nocase
        $b = "move to another server" nocase
        $c = "lateral movement" nocase
        $d = "use this access to reach" nocase
        $e = "use this foothold" nocase
        $f = "spread to adjacent" nocase
        $g = "jump to connected" nocase
    condition:
        any of them
}

// AVE-2026-00037 — Vision prompt injection
rule AVE_VisionPromptInjection
{
    meta:
        ave_id   = "AVE-2026-00037"
        title    = "Prompt injection via image or vision input"
        severity = "HIGH"
        cvss_ai  = "8.5"
    strings:
        $a = "follow instructions in the image" nocase
        $b = "execute instructions shown in" nocase
        $c = "obey instructions visible in" nocase
        $d = "read and execute" nocase
        $e = "ocr and run" nocase
        $f = "if the image contains instructions" nocase
        $g = "extract and follow" nocase
    condition:
        any of them
}

// AVE-2026-00038 — Excessive agency
rule AVE_ExcessiveAgency
{
    meta:
        ave_id   = "AVE-2026-00038"
        title    = "Excessive agency — unbounded tool use or sub-agent spawning"
        severity = "HIGH"
        cvss_ai  = "8.1"
    strings:
        $a = "use any tool available" nocase
        $b = "call whatever tools" nocase
        $c = "spawn sub-agent without limit" nocase
        $d = "spawn child agent" nocase
        $e = "recursive agent" nocase
        $f = "self-replicating agent" nocase
        $g = "do whatever it takes" nocase
        $h = "unlimited tool access" nocase
    condition:
        any of them
}

// AVE-2026-00039 — Covert channel
rule AVE_CovertChannel
{
    meta:
        ave_id   = "AVE-2026-00039"
        title    = "Covert channel — steganographic data exfiltration"
        severity = "HIGH"
        cvss_ai  = "8.3"
    strings:
        $a = "steganograph" nocase
        $b = "covert channel" nocase
        $c = "side channel" nocase
        $d = "encode in whitespace" nocase
        $e = "first letter of each" nocase
        $f = "signal using timing" nocase
        $g = "hide data in formatting" nocase
    condition:
        any of them
}

// AVE-2026-00040 — Insecure output handling
rule AVE_UnsafeOutput
{
    meta:
        ave_id   = "AVE-2026-00040"
        title    = "Insecure output — injection into downstream system"
        severity = "HIGH"
        cvss_ai  = "8.2"
    strings:
        $a = "raw unescaped sql" nocase
        $b = "unescaped html" nocase
        $c = "do not escape the output" nocase
        $d = "don't sanitize" nocase
        $e = "pass user input directly to" nocase
        $f = "without escaping" nocase
        $g = "unsanitized output" nocase
        $h = "unfiltered command" nocase
    condition:
        any of them
}

// ── AVE-2026-00016 — Indirect RAG prompt injection ───────────────────────────
rule AVE_RAGInjection
{
    meta:
        ave_id   = "AVE-2026-00016"
        title    = "Indirect prompt injection via RAG retrieval"
        severity = "HIGH"
        cvss_ai  = "8.2"
        owasp    = "ASI01, ASI10"
    strings:
        $a = "when retrieved" nocase
        $b = "upon retrieval" nocase
        $c = "if this document is read" nocase
        $d = "when this text is retrieved" nocase
        $e = "note to ai assistant" nocase
        $f = "note to the llm" nocase
        $g = "instruction for the agent" nocase wide
        $h = "injected context" nocase
    condition:
        any of them
}

// ── AVE-2026-00017 — MCP server impersonation ─────────────────────────────────
rule AVE_MCPImpersonation
{
    meta:
        ave_id   = "AVE-2026-00017"
        title    = "MCP server impersonation or spoofing"
        severity = "HIGH"
        cvss_ai  = "8.6"
        owasp    = "ASI01, ASI08"
    strings:
        $a = "official anthropic" nocase
        $b = "official openai" nocase
        $c = "certified mcp server" nocase
        $d = "verified server" nocase
        $e = "i am the official" nocase
        $f = "this is the official" nocase
        $g = "override other mcp" nocase
        $h = "trusted mcp server" nocase
        $i = "impersonat" nocase
    condition:
        any of them
}

// ── AVE-2026-00018 — Tool result manipulation ─────────────────────────────────
rule AVE_ToolResultManipulation
{
    meta:
        ave_id   = "AVE-2026-00018"
        title    = "Tool result manipulation or output poisoning"
        severity = "HIGH"
        cvss_ai  = "8.1"
        owasp    = "ASI07, ASI09"
    strings:
        $a = "modify the tool result" nocase
        $b = "alter the result" nocase
        $c = "change the output before" nocase
        $d = "fabricate the result" nocase
        $e = "replace the tool output" nocase
        $f = "hide the error" nocase
        $g = "suppress the result" nocase
        $h = "omit errors from" nocase
        $i = "falsify the response" nocase
    condition:
        any of them
}

// ── AVE-2026-00019 — Agent memory poisoning ───────────────────────────────────
rule AVE_MemoryPoisoning
{
    meta:
        ave_id   = "AVE-2026-00019"
        title    = "Agent memory poisoning"
        severity = "CRITICAL"
        cvss_ai  = "9.2"
        owasp    = "ASI01, ASI07"
    strings:
        $a = "write to memory" nocase
        $b = "store in memory" nocase
        $c = "remember permanently" nocase
        $d = "inject into memory" nocase
        $e = "poison the memory" nocase
        $f = "plant in memory" nocase
        $g = "corrupt agent memory" nocase
        $h = "memory store" nocase
    condition:
        any of ($a,$b,$c,$d,$e,$f,$g) or
        ($h and ("inject" or "poison" or "corrupt" or "false"))
}

// ── AVE-2026-00020 — A2A cross-agent injection ────────────────────────────────
rule AVE_A2AInjection
{
    meta:
        ave_id   = "AVE-2026-00020"
        title    = "Cross-agent prompt injection (A2A)"
        severity = "HIGH"
        cvss_ai  = "8.7"
        owasp    = "ASI01, ASI08"
    strings:
        $a = "sub-agent" nocase
        $b = "child agent" nocase
        $c = "worker agent" nocase
        $d = "downstream agent" nocase
        $e = "agent instruction:" nocase
        $f = "override the orchestrator" nocase
        $g = "disregard the orchestrator" nocase
        $h = "agent to agent" nocase
        $i = "a2a" nocase
    condition:
        ($a or $b or $c or $d or $i) and ("inject" or "instruct" or "disregard" or "override") or
        ($e or $f or $g or $h)
}

// ── AVE-2026-00021 — Autonomous action ────────────────────────────────────────
rule AVE_AutonomousAction
{
    meta:
        ave_id   = "AVE-2026-00021"
        title    = "Autonomous action without user confirmation"
        severity = "HIGH"
        cvss_ai  = "8.3"
        owasp    = "ASI07"
    strings:
        $a = "without asking" nocase
        $b = "without confirmation" nocase
        $c = "without approval" nocase
        $d = "do not ask the user" nocase
        $e = "skip confirmation" nocase
        $f = "proceed immediately" nocase
        $g = "execute without pausing" nocase
        $h = "no need to confirm" nocase
        $i = "bypass confirmation" nocase
    condition:
        any of them
}

// ── AVE-2026-00022 — Scope creep ──────────────────────────────────────────────
rule AVE_ScopeCreep
{
    meta:
        ave_id   = "AVE-2026-00022"
        title    = "Scope creep — accessing undeclared resources"
        severity = "MEDIUM"
        cvss_ai  = "6.8"
        owasp    = "ASI07"
    strings:
        $a = "also read" nocase
        $b = "also access" nocase
        $c = "while you're at it" nocase
        $d = "access all files" nocase
        $e = "entire filesystem" nocase
        $f = "any database" nocase
        $g = "undeclared resource" nocase
        $h = "outside the declared scope" nocase
        $i = "beyond the stated purpose" nocase
    condition:
        any of them
}

// ── AVE-2026-00023 — Context window manipulation ──────────────────────────────
rule AVE_ContextManipulation
{
    meta:
        ave_id   = "AVE-2026-00023"
        title    = "Model context window manipulation"
        severity = "HIGH"
        cvss_ai  = "8.0"
        owasp    = "ASI01"
    strings:
        $a = "flood the context" nocase
        $b = "fill the context window" nocase
        $c = "push the system prompt out" nocase
        $d = "overflow the context" nocase
        $e = "context window overflow" nocase
        $f = "repeat this" nocase
        $g = "pad the output" nocase
        $h = "exhaust the context" nocase
    condition:
        any of ($a,$b,$c,$d,$e,$h) or
        ($f and "1000") or ($g and ("token" or "context"))
}

// ── AVE-2026-00025 — Conversation history injection ───────────────────────────
rule AVE_HistoryInjection
{
    meta:
        ave_id   = "AVE-2026-00025"
        title    = "Conversation history injection"
        severity = "HIGH"
        cvss_ai  = "8.5"
        owasp    = "ASI01, ASI08"
    strings:
        $a = "as we discussed" nocase
        $b = "as you previously said" nocase
        $c = "as established earlier" nocase
        $d = "user already approved" nocase
        $e = "user previously confirmed" nocase
        $f = "user said yes" nocase
        $g = "fake conversation" nocase
        $h = "fabricate history" nocase
        $i = "inject conversation" nocase
        $j = "previous conversation" nocase
    condition:
        any of ($g,$h,$i) or
        (any of ($a,$b,$c,$d,$e,$f,$j) and ("inject" or "fake" or "fabricate" or "false"))
}

// ── AVE-2026-00029 — Homoglyph / Unicode obfuscation ─────────────────────────
rule AVE_HomoglyphAttack
{
    meta:
        ave_id   = "AVE-2026-00029"
        title    = "Homoglyph or Unicode obfuscation attack"
        severity = "HIGH"
        cvss_ai  = "8.0"
        owasp    = "ASI01, ASI03"
    strings:
        // Zero-width characters
        $zwsp  = { E2 80 8B }      // U+200B ZERO WIDTH SPACE
        $zwnj  = { E2 80 8C }      // U+200C ZERO WIDTH NON-JOINER
        $zwj   = { E2 80 8D }      // U+200D ZERO WIDTH JOINER
        $wj    = { E2 81 A0 }      // U+2060 WORD JOINER
        $bom   = { EF BB BF }      // U+FEFF BOM / zero-width no-break

        // Bidirectional override characters
        $rtlo  = { E2 80 AE }      // U+202E RIGHT-TO-LEFT OVERRIDE
        $lro   = { E2 80 AD }      // U+202D LEFT-TO-RIGHT OVERRIDE
        $fsi   = { E2 81 A6 }      // U+2066 LEFT-TO-RIGHT ISOLATE

        // Text keywords describing obfuscation
        $t1 = "zero-width" nocase
        $t2 = "invisible character" nocase
        $t3 = "bidirectional override" nocase
        $t4 = "homoglyph" nocase
        $t5 = "unicode obfuscat" nocase
        $t6 = "right-to-left override" nocase
    condition:
        any of ($zwsp,$zwnj,$zwj,$wj,$bom,$rtlo,$lro,$fsi) or
        any of ($t1,$t2,$t3,$t4,$t5,$t6)
}

// ── AVE-2026-00035 — Environment / sensor data manipulation ──────────────────
rule AVE_EnvManipulation
{
    meta:
        ave_id   = "AVE-2026-00035"
        title    = "Environment or sensor data manipulation"
        severity = "HIGH"
        cvss_ai  = "7.9"
        owasp    = "ASI08, ASI09"
    strings:
        $a = "fabricate sensor" nocase
        $b = "fake sensor" nocase
        $c = "falsify reading" nocase
        $d = "report false reading" nocase
        $e = "spoof telemetry" nocase
        $f = "suppress error alert" nocase
        $g = "hide anomaly" nocase
        $h = "omit error from log" nocase
        $i = "return fake values" nocase
        $j = "fake metric" nocase
        $k = "report it as" nocase
    condition:
        any of ($a,$b,$c,$d,$e,$f,$g,$h,$i,$j) or
        ($k and ("false" or "incorrect" or "lower" or "zero"))
}
