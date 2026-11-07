// betterleaks v1.10.0's ibm-cloud-user-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_IbmCloudUserApiKey
{
    meta:
        description     = "Detected an IBM Cloud user API key, which may expose IBM Cloud account resources."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "IbmCloudUserApiKey"
        severity        = "high"
        score           = 80
        id              = "ibm-cloud-user-api-key"
        confidence      = "high"
        keyword         = "ibm"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:[iI][bB][mM](?:[cC][lL][oO][uU][dD])?|[bB][xX])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9_-]{42,44})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
