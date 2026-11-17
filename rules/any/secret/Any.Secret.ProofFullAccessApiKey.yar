// betterleaks v1.10.0's proof-full-access-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_ProofFullAccessApiKey
{
    meta:
        description       = "Proof production full-access API key."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "ProofFullAccessApiKey"
        severity          = "high"
        score             = 80
        id                = "proof-full-access-api-key"
        confidence        = "high"
        keyword           = "prf_"
        skip_regex_secret = "^prf_(?:cli_)?test_"  // gitleaks:allow
        skip_entropy_lt   = "3.5"

    strings:
        $secret = /\b(prf_(?:cli_)?[A-Za-z0-9_-]{20,80})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
