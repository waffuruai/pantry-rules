// betterleaks v1.10.0's auth0-client-id.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_Auth0ClientId1
{
    meta:
        description     = "Auth0 client ID, used as a component of the Auth0 client-secret composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "Auth0ClientId1"
        severity        = "medium"
        score           = 50
        id              = "auth0-client-id.1"
        confidence      = "medium"
        keyword         = "auth0"
        skip_entropy_lt = "3.0"

    strings:
        $secret = /(?:(?:[aA][uU][tT][hH]0[_.-]?(?:[cC][lL][iI][eE][nN][tT][_.-]?)?(?:[iI][dD]|[iI][dD][eE][nN][tT][iI][fF][iI][eE][rR]))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9_-]{32,60})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
