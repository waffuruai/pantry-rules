// betterleaks v1.10.0's instantly-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_InstantlyApiKey1
{
    meta:
        description     = "Instantly API key, which may allow access to campaigns, accounts, leads, and analytics."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "InstantlyApiKey1"
        severity        = "medium"
        score           = 50
        id              = "instantly-api-key.1"
        confidence      = "medium"
        keyword         = "instantly"
        skip_entropy_lt = "3.3"

    strings:
        $secret = /(?:(?:[iI][nN][sS][tT][aA][nN][tT][lL][yY])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9+\/]{66}==)(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
