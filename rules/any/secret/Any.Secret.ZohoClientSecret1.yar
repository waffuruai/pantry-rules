// betterleaks v1.10.0's zoho-client-secret.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_ZohoClientSecret1
{
    meta:
        description       = "Zoho OAuth client secret, which may allow OAuth client authentication when paired with the associated client ID."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "ZohoClientSecret1"
        severity          = "high"
        score             = 80
        id                = "zoho-client-secret.1"
        confidence        = "high"
        keyword           = "zoho"
        component1        = "zoho-client-id.1"
        component1_within = "5L"
        skip_entropy_lt   = "3.5"

    strings:
        $secret = /(?:[zZ][oO][hH][oO])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Fa-f0-9]{42})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
