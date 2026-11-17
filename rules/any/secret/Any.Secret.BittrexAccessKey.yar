// betterleaks v1.10.0's bittrex-access-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_BittrexAccessKey
{
    meta:
        description         = "Identified a Bittrex Access Key, which could lead to unauthorized access to cryptocurrency trading accounts and financial loss."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "BittrexAccessKey"
        severity            = "high"
        score               = 80
        id                  = "bittrex-access-key"
        confidence          = "high"
        keyword             = "bittrex"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[bB][iI][tT][tT][rR][eE][xX])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{32})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
