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
