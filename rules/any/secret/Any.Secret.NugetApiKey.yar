// betterleaks v1.10.0's nuget-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_NugetApiKey
{
    meta:
        description     = "Detected a NuGet API key, which can push, unlist, or deprecate packages on nuget.org on behalf of its owner."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "NugetApiKey"
        severity        = "high"
        score           = 80
        id              = "nuget-api-key"
        confidence      = "high"
        keyword         = "oy2"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /\b([oO][yY]2[A-Pa-p][A-Za-z2-7]{15}[AQaq][A-Za-z2-7]{25}[AEIMQUYaeimquy4])(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
