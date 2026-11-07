// betterleaks v1.10.0's ovh-application-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_OvhApplicationSecret
{
    meta:
        description       = "OVHcloud Application Secret - component of authenticated OVH API requests, which could allow unauthorized access to OVHcloud infrastructure when combined with Application and Consumer keys."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "OvhApplicationSecret"
        severity          = "high"
        score             = 80
        id                = "ovh-application-secret"
        confidence        = "high"
        keyword           = "ovh"
        component1        = "ovh-application-key"
        component1_within = "20L"
        component2        = "ovh-consumer-key"
        component2_within = "20L"
        skip_entropy_le   = "3.0"

    strings:
        $secret = /(?:[aA][pP][pP](?:[lL][iI][cC][aA][tT][iI][oO][nN])?[_.-]{0,1}[sS][eE][cC][rR][eE][tT])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-ZA-Za-z0-9-]{32})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
