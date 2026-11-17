// betterleaks v1.10.0's discord-client-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_DiscordClientId
{
    meta:
        description     = "Identified a Discord client ID, which may lead to unauthorized integrations and data exposure in Discord applications."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "DiscordClientId"
        severity        = "medium"
        score           = 50
        id              = "discord-client-id"
        confidence      = "medium"
        keyword         = "discord"
        skip_entropy_lt = "2.75"

    strings:
        $secret = /(?:[dD][iI][sS][cC][oO][rR][dD])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9]{18})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
