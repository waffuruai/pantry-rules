// betterleaks v1.10.0's zoho-zapi-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_ZohoZapiKey1
{
    meta:
        description     = "Zoho ZAPI key, which may authorize CRM functions, extensions, webhooks, or other Zoho APIs."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ZohoZapiKey1"
        severity        = "high"
        score           = 80
        id              = "zoho-zapi-key.1"
        confidence      = "high"
        keyword         = "zoho"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:[zZ][oO][hH][oO])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}((?:1001\.[A-Fa-f0-9]{32}\.[A-Fa-f0-9]{32}(?:-[dD])?|1003\.[A-Fa-f0-9]{32,64}))(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
