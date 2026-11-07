// betterleaks v1.10.0's wakatime-api-key.2 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_WakatimeApiKey2
{
    meta:
        description     = "WakaTime API key version 2 (waka_ format)."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "WakatimeApiKey2"
        severity        = "high"
        score           = 80
        id              = "wakatime-api-key.2"
        confidence      = "high"
        keyword         = "waka_"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /\b([wW][aA][kK][aA]_[A-Za-z0-9]{36,64})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
