// betterleaks v1.10.0's deno-account-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_DenoAccountToken
{
    meta:
        description     = "Detected a Deno account token, which may expose Deno Deploy account access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "DenoAccountToken"
        severity        = "high"
        score           = 80
        id              = "deno-account-token"
        confidence      = "high"
        keyword         = "ddp_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(ddp_[A-Za-z0-9]{36})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
