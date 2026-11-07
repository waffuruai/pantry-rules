// betterleaks v1.10.0's miro-client-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_MiroClientId
{
    meta:
        description     = "Detected a Miro OAuth client ID, used as a component of the miro-client-secret composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "MiroClientId"
        severity        = "medium"
        score           = 50
        id              = "miro-client-id"
        confidence      = "medium"
        keyword         = "miro"
        skip_entropy_lt = "2.5"

    strings:
        $secret = /(?:[mM][iI][rR][oO][_. -]*[cC][lL][iI][eE][nN][tT][_. -]*[iI][dD])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9]{15,21})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
