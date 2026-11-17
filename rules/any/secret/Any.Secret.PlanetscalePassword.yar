// betterleaks v1.10.0's planetscale-password rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_PlanetscalePassword
{
    meta:
        description     = "Discovered a PlanetScale password, which could lead to unauthorized database operations and data breaches."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "PlanetscalePassword"
        severity        = "high"
        score           = 80
        id              = "planetscale-password"
        confidence      = "high"
        keyword         = "pscale_pw_"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b([pP][sS][cC][aA][lL][eE]_[pP][wW]_[\w=\.-]{32,64})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
