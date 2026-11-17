// betterleaks v1.10.0's monday-api-token.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_MondayApiToken1
{
    meta:
        description     = "monday.com API token, which may grant the same workspace access as its associated user or application."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "MondayApiToken1"
        severity        = "high"
        score           = 80
        id              = "monday-api-token.1"
        confidence      = "high"
        keyword         = "monday"
        specificity     = 110
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:(?:[mM][oO][nN][dD][aA][yY])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(eyJ[A-Za-z0-9_-]{10,200}\.eyJ[A-Za-z0-9_-]{50,1000}\.[A-Za-z0-9_-]{20,500})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
