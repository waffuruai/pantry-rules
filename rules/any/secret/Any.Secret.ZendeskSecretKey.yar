// betterleaks v1.10.0's zendesk-secret-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_ZendeskSecretKey
{
    meta:
        description         = "Detected a Zendesk Secret Key, risking unauthorized access to customer support services and sensitive ticketing data."
        author              = "betterleaks"
        reference           = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license             = "MIT"
        os                  = "any"
        category            = "secret"
        family              = "ZendeskSecretKey"
        severity            = "high"
        score               = 80
        id                  = "zendesk-secret-key"
        confidence          = "high"
        keyword             = "zendesk"
        skip_entropy_lt     = "3.5"
        skip_token_ratio_ge = "2.5"

    strings:
        $secret = /(?:[zZ][eE][nN][dD][eE][sS][kK])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{40})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
