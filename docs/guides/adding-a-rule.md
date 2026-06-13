# Adding a Detection Rule

Every new detection rule requires:

1. Positive fixture: tests/fixtures/skills/malicious/[rule-name].md
   A file that TRIGGERS the rule.

2. Negative fixture: tests/fixtures/skills/clean/[rule-name]-clean.md
   A similar file that does NOT trigger the rule.

3. Rule definition in the appropriate engine file.

4. AVE record reference (link to existing AVE or create new one at github.com/bawbel/ave).

5. Tests for both fixtures:
   def test_detects_[rule_name](tmp_path):
       ...
       assert len(result.findings) >= 1
       assert result.findings[0].rule_id == "bawbel-[rule-name]"

   def test_no_fp_[rule_name]_clean(tmp_path):
       ...
       assert result.is_clean

## Rule naming

rule_id: kebab-case, prefix "bawbel-", never change once published
Example: "bawbel-external-fetch", "bawbel-goal-override"

## Severity guide

CRITICAL (AIVSS 9+): complete attack path, immediate action
HIGH (7-8.9): significant risk, schedule remediation
MEDIUM (4-6.9): risk factor, review
LOW (<4): best practice, informational
