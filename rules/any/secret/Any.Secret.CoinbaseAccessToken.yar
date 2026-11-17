// betterleaks v1.10.0's coinbase-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_CoinbaseAccessToken
{
    meta:
        description         = "Detected a Coinbase Access Token, posing a risk of unauthorized access to cryptocurrency accounts and financial transactions."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "CoinbaseAccessToken"
        severity            = "medium"
        score               = 50
        id                  = "coinbase-access-token"
        confidence          = "medium"
        keyword             = "coinbase"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[cC][oO][iI][nN][bB][aA][sS][eE])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9_-]{64})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
