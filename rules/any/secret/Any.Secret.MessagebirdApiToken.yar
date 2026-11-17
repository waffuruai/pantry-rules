// betterleaks v1.10.0's messagebird-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_MessagebirdApiToken
{
    meta:
        description         = "Found a MessageBird API token, risking unauthorized access to communication platforms and message data."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "MessagebirdApiToken"
        severity            = "high"
        score               = 80
        id                  = "messagebird-api-token"
        confidence          = "high"
        keyword             = "messagebird"
        keyword             = "message-bird"
        keyword             = "message_bird"
        skip_entropy_lt     = "3.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[mM][eE][sS][sS][aA][gG][eE][_-]?[bB][iI][rR][dD])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{25})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
