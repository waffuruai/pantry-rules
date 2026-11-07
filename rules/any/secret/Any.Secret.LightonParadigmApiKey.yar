// betterleaks v1.10.0's lighton-paradigm-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_LightonParadigmApiKey
{
    meta:
        description         = "Detected a LightOn Paradigm API key, which may expose enterprise LLM services to unauthorized access."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "LightonParadigmApiKey"
        severity            = "medium"
        score               = 50
        id                  = "lighton-paradigm-api-key"
        confidence          = "medium"
        keyword             = "lighton"
        keyword             = "paradigm"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[lL][iI][gG][hH][tT][oO][nN]|[pP][aA][rR][aA][dD][iI][gG][mM])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-ZA-Za-z0-9_\-]{40,80})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
