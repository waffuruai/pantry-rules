// betterleaks v1.10.0's vault-batch-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_VaultBatchToken
{
    meta:
        description     = "Detected a Vault Batch Token, risking unauthorized access to secret management services and sensitive data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "VaultBatchToken"
        severity        = "high"
        score           = 80
        id              = "vault-batch-token"
        confidence      = "high"
        keyword         = "hvb."
        skip_entropy_le = "4.0"

    strings:
        $secret = /\b(hvb\.[\w-]{138,300})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
