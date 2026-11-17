// betterleaks v1.10.0's etsy-open-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_EtsyOpenApiKey
{
    meta:
        description     = "Found an Etsy Open API key, potentially compromising Etsy app access and shop integrations."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "EtsyOpenApiKey"
        severity        = "high"
        score           = 80
        id              = "etsy-open-api-key"
        confidence      = "high"
        keyword         = "etsy"
        keyword         = "x-api-key"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /(?:[eE][tT][sS][yY]|[xX]-[aA][pP][iI]-[kK][eE][yY])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{24}:[A-Za-z0-9]{10,64})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
