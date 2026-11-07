// betterleaks v1.10.0's datadog-application-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_DatadogApplicationKey
{
    meta:
        description     = "Detected a Datadog application key, which may expose Datadog account and monitoring data when paired with an API key."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "DatadogApplicationKey"
        severity        = "high"
        score           = 80
        id              = "datadog-application-key"
        confidence      = "high"
        keyword         = "datadog"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:[dD][aA][tT][aA][dD][oO][gG])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-ZA-Za-z0-9-]{40})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
