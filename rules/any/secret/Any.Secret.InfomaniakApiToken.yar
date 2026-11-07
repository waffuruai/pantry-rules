// betterleaks v1.10.0's infomaniak-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_InfomaniakApiToken
{
    meta:
        description         = "Detected an Infomaniak API token, which may expose hosting, mail, and cloud services to unauthorized access."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "InfomaniakApiToken"
        severity            = "high"
        score               = 80
        id                  = "infomaniak-api-token"
        confidence          = "high"
        keyword             = "infomaniak"
        skip_entropy_lt     = "4.0"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[iI][nN][fF][oO][mM][aA][nN][iI][aA][kK])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-ZA-Za-z0-9_\-]{60,100})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
