// betterleaks v1.10.0's vault-service-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_VaultServiceToken
{
    meta:
        description       = "Identified a Vault Service Token, potentially compromising infrastructure security and access to sensitive credentials."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "VaultServiceToken"
        severity          = "high"
        score             = 80
        id                = "vault-service-token"
        confidence        = "high"
        keyword           = "hvs."
        keyword           = "vault"
        skip_entropy_le   = "3.5"
        skip_regex_secret = "s\\.[A-Za-z]{24}"  // gitleaks:allow

    strings:
        $secret = /\b((?:hvs\.[\w-]{90,120}|s\.(?:[A-Za-z0-9]{24})))(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
