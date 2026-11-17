// betterleaks v1.10.0's asana-client-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_AsanaClientId
{
    meta:
        description     = "Discovered a potential Asana Client ID, risking unauthorized access to Asana projects and sensitive task information."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "AsanaClientId"
        severity        = "high"
        score           = 80
        id              = "asana-client-id"
        confidence      = "high"
        keyword         = "asana"
        skip_entropy_lt = "2.75"

    strings:
        $secret = /(?:[aA][sS][aA][nN][aA])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9]{16})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
