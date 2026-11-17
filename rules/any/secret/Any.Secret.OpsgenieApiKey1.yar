// betterleaks v1.10.0's opsgenie-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_OpsgenieApiKey1
{
    meta:
        description     = "Opsgenie API key, which may allow access to alerts, incidents, and account configuration."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "OpsgenieApiKey1"
        severity        = "high"
        score           = 80
        id              = "opsgenie-api-key.1"
        confidence      = "high"
        keyword         = "opsgenie"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /(?:[oO][pP][sS][gG][eE][nN][iI][eE])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-F0-9a-f]{8}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{12})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
