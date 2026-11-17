// betterleaks v1.10.0's frameio-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_FrameioApiToken
{
    meta:
        description     = "Found a Frame.io API token, potentially compromising video collaboration and project management."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "FrameioApiToken"
        severity        = "high"
        score           = 80
        id              = "frameio-api-token"
        confidence      = "high"
        keyword         = "fio-u-"
        skip_entropy_lt = "3.3"

    strings:
        $secret = /fio-u-[A-Za-z0-9\-_=]{64}/  // gitleaks:allow

    condition:
        $secret
}
