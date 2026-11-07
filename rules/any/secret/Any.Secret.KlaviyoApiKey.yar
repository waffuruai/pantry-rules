// betterleaks v1.10.0's klaviyo-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_KlaviyoApiKey
{
    meta:
        description     = "Detected a Klaviyo API key, which may expose Klaviyo account and marketing data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "KlaviyoApiKey"
        severity        = "high"
        score           = 80
        id              = "klaviyo-api-key"
        confidence      = "high"
        keyword         = "klaviyo"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:[kK][lL][aA][vV][iI][yY][oO])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([pP][kK]_[A-Za-z0-9]{34})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
