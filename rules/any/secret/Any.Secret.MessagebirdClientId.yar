// betterleaks v1.10.0's messagebird-client-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_MessagebirdClientId
{
    meta:
        description         = "Discovered a MessageBird client ID, potentially compromising API integrations and sensitive communication data."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "MessagebirdClientId"
        severity            = "high"
        score               = 80
        id                  = "messagebird-client-id"
        confidence          = "high"
        keyword             = "messagebird"
        keyword             = "message-bird"
        keyword             = "message_bird"
        skip_entropy_lt     = "3.3"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[mM][eE][sS][sS][aA][gG][eE][_-]?[bB][iI][rR][dD])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-F0-9a-f]{8}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{12})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
