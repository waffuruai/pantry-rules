// betterleaks v1.10.0's confluent-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_ConfluentAccessToken
{
    meta:
        description         = "Identified a Confluent Access Token, which could compromise access to streaming data platforms and sensitive data flow."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "ConfluentAccessToken"
        severity            = "high"
        score               = 80
        id                  = "confluent-access-token"
        confidence          = "high"
        keyword             = "confluent"
        skip_entropy_lt     = "3.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[cC][oO][nN][fF][lL][uU][eE][nN][tT])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{16})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
