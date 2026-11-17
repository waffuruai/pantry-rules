// betterleaks v1.10.0's configcat-sdk-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_ConfigcatSdkKey
{
    meta:
        description     = "Detected a ConfigCat SDK key, which may allow access to feature flag configuration data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ConfigcatSdkKey"
        severity        = "high"
        score           = 80
        id              = "configcat-sdk-key"
        confidence      = "high"
        keyword         = "configcat"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:[cC][oO][nN][fF][iI][gG][cC][aA][tT])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-ZA-Za-z0-9_-]{22}\/[a-zA-ZA-Za-z0-9_-]{22})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
