// betterleaks v1.10.0's digitalocean-refresh-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_DigitaloceanRefreshToken
{
    meta:
        description = "Uncovered a DigitalOcean OAuth Refresh Token, which could allow prolonged unauthorized access and resource manipulation."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "DigitaloceanRefreshToken"
        severity    = "high"
        score       = 80
        id          = "digitalocean-refresh-token"
        confidence  = "high"
        keyword     = "dor_v1_"

    strings:
        $secret = /\b([dD][oO][rR]_[vV]1_[A-Fa-f0-9]{64})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
