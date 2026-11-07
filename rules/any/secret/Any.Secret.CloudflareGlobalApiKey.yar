// betterleaks v1.10.0's cloudflare-global-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_CloudflareGlobalApiKey
{
    meta:
        description         = "Detected a Cloudflare Global API Key, potentially compromising cloud application deployments and operational security."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "CloudflareGlobalApiKey"
        severity            = "high"
        score               = 80
        id                  = "cloudflare-global-api-key"
        confidence          = "high"
        keyword             = "cloudflare"
        skip_entropy_lt     = "3.3"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[cC][lL][oO][uU][dD][fF][lL][aA][rR][eE])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Fa-f0-9]{37})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
