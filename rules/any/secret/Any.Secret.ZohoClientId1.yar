// betterleaks v1.10.0's zoho-client-id.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_ZohoClientId1
{
    meta:
        description     = "Zoho OAuth client ID, used as a component of the zoho-client-secret.1 composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "ZohoClientId1"
        severity        = "medium"
        score           = 50
        id              = "zoho-client-id.1"
        confidence      = "medium"
        keyword         = "zoho"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /(?:[zZ][oO][hH][oO])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(1000\.[A-Za-z0-9]{30})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
