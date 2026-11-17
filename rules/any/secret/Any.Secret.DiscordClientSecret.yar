// betterleaks v1.10.0's discord-client-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_DiscordClientSecret
{
    meta:
        description         = "Discovered a potential Discord client secret, risking compromised Discord bot integrations and data leaks."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "DiscordClientSecret"
        severity            = "medium"
        score               = 50
        id                  = "discord-client-secret"
        confidence          = "medium"
        keyword             = "discord"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[dD][iI][sS][cC][oO][rR][dD])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9=_\-]{32})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
