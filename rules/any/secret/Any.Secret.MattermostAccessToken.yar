// betterleaks v1.10.0's mattermost-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_MattermostAccessToken
{
    meta:
        description         = "Identified a Mattermost Access Token, which may compromise team communication channels and data privacy."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "MattermostAccessToken"
        severity            = "medium"
        score               = 50
        id                  = "mattermost-access-token"
        confidence          = "medium"
        keyword             = "mattermost"
        skip_entropy_lt     = "3.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[mM][aA][tT][tT][eE][rR][mM][oO][sS][tT])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{26})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
