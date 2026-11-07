// betterleaks v1.10.0's new-relic-user-api-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_NewRelicUserApiId
{
    meta:
        description         = "Found a New Relic user API ID, posing a risk to application monitoring services and data integrity."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "NewRelicUserApiId"
        severity            = "high"
        score               = 80
        id                  = "new-relic-user-api-id"
        confidence          = "high"
        keyword             = "new-relic"
        keyword             = "newrelic"
        keyword             = "new_relic"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[nN][eE][wW]-[rR][eE][lL][iI][cC]|[nN][eE][wW][rR][eE][lL][iI][cC]|[nN][eE][wW]_[rR][eE][lL][iI][cC])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{64})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
