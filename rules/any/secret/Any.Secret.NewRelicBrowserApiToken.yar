// betterleaks v1.10.0's new-relic-browser-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_NewRelicBrowserApiToken
{
    meta:
        description         = "Identified a New Relic ingest browser API token, risking unauthorized access to application performance data and analytics."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "NewRelicBrowserApiToken"
        severity            = "high"
        score               = 80
        id                  = "new-relic-browser-api-token"
        confidence          = "high"
        keyword             = "nrjs-"
        skip_entropy_lt     = "3.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[nN][eE][wW]-[rR][eE][lL][iI][cC]|[nN][eE][wW][rR][eE][lL][iI][cC]|[nN][eE][wW]_[rR][eE][lL][iI][cC])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([Nn][Rr][Jj][Ss]-[A-Fa-f0-9]{19})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
