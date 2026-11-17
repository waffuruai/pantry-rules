// betterleaks v1.10.0's wiz-client-id.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_WizClientId1
{
    meta:
        description     = "Wiz OAuth client ID, used as a component of the Wiz client-secret composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "WizClientId1"
        severity        = "medium"
        score           = 50
        id              = "wiz-client-id.1"
        confidence      = "medium"
        keyword         = "wiz"
        skip_entropy_lt = "4.0"

    strings:
        $secret = /(?:(?:[wW][iI][zZ])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{53,56})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
