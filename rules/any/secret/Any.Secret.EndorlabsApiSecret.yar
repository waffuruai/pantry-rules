// betterleaks v1.10.0's endorlabs-api-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_EndorlabsApiSecret
{
    meta:
        description     = "Detected an Endor Labs API Secret, which together with an API key grants full access to Endor Labs supply chain security services."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "EndorlabsApiSecret"
        severity        = "high"
        score           = 80
        id              = "endorlabs-api-secret"
        confidence      = "high"
        keyword         = "endr+"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:[eE][nN][dD][oO][rR](?:[lL][aA][bB][sS])?|[sS][eE][cC][rR][eE][tT])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([eE][nN][dD][rR]\+[a-zA-ZA-Za-z0-9-]{16})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
