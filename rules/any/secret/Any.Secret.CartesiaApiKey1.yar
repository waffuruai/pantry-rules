// betterleaks v1.10.0's cartesia-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_CartesiaApiKey1
{
    meta:
        description     = "Cartesia API key, which grants server-side access to Cartesia voice APIs."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "CartesiaApiKey1"
        severity        = "high"
        score           = 80
        id              = "cartesia-api-key.1"
        confidence      = "high"
        keyword         = "sk_car_"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b(sk_car_[A-Za-z0-9_]{20})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
