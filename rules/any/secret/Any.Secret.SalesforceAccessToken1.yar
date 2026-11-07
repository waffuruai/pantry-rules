// betterleaks v1.10.0's salesforce-access-token.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_SalesforceAccessToken1
{
    meta:
        description       = "Salesforce access token."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "SalesforceAccessToken1"
        severity          = "high"
        score             = 80
        id                = "salesforce-access-token.1"
        confidence        = "high"
        keyword           = "salesforce.com"
        component1        = "salesforce-instance-url.1"
        component1_within = "30L"
        skip_entropy_lt   = "3.3"

    strings:
        $secret = /\b(00[A-Za-z0-9]{13}![A-Za-z0-9._-]{80,260})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
