// betterleaks v1.10.0's endorlabs-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_EndorlabsApiKey
{
    meta:
        description     = "Detected an Endor Labs API Key, which may compromise supply chain security scanning and software composition analysis."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "EndorlabsApiKey"
        severity        = "high"
        score           = 80
        id              = "endorlabs-api-key"
        confidence      = "high"
        keyword         = "endr+"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /(?:[eE][nN][dD][oO][rR](?:[lL][aA][bB][sS])?|[kK][eE][yY])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([eE][nN][dD][rR]\+[a-zA-ZA-Za-z0-9-]{16})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
