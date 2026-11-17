// betterleaks v1.10.0's digitalocean-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_DigitaloceanAccessToken
{
    meta:
        description     = "Found a DigitalOcean OAuth Access Token, risking unauthorized cloud resource access and data compromise."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "DigitaloceanAccessToken"
        severity        = "high"
        score           = 80
        id              = "digitalocean-access-token"
        confidence      = "high"
        keyword         = "doo_v1_"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b(doo_v1_[a-f0-9]{64})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
