// betterleaks v1.10.0's wiz-client-secret.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_WizClientSecret1
{
    meta:
        description       = "Wiz OAuth client secret, which may allow access to the Wiz API when paired with its client ID."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "WizClientSecret1"
        severity          = "high"
        score             = 80
        id                = "wiz-client-secret.1"
        confidence        = "high"
        keyword           = "wiz"
        component1        = "wiz-client-id.1"
        component1_within = "5L"
        skip_entropy_lt   = "4.0"

    strings:
        $secret = /(?:(?:[wW][iI][zZ])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{64})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
