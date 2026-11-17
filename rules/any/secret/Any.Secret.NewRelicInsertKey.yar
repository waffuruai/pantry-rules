// betterleaks v1.10.0's new-relic-insert-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_NewRelicInsertKey
{
    meta:
        description         = "Discovered a New Relic insight insert key, compromising data injection into the platform."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "NewRelicInsertKey"
        severity            = "high"
        score               = 80
        id                  = "new-relic-insert-key"
        confidence          = "high"
        keyword             = "nrii-"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[nN][eE][wW]-[rR][eE][lL][iI][cC]|[nN][eE][wW][rR][eE][lL][iI][cC]|[nN][eE][wW]_[rR][eE][lL][iI][cC])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([Nn][Rr][Ii][Ii]-[A-Za-z0-9-]{32})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
