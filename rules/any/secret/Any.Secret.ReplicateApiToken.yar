// betterleaks v1.10.0's replicate-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_ReplicateApiToken
{
    meta:
        description     = "Detected a Replicate API Token, which may expose AI model hosting and inference services to unauthorized access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ReplicateApiToken"
        severity        = "high"
        score           = 80
        id              = "replicate-api-token"
        confidence      = "high"
        keyword         = "r8_"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b([rR]8_[a-zA-ZA-Za-z0-9]{37})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
