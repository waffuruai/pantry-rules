// betterleaks v1.10.0's auth0-client-secret.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_Auth0ClientSecret1
{
    meta:
        description       = "Auth0 client secret, which may allow an application to impersonate its OAuth client."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "Auth0ClientSecret1"
        severity          = "high"
        score             = 80
        id                = "auth0-client-secret.1"
        confidence        = "high"
        keyword           = "auth0"
        component1        = "auth0-client-id.1"
        component1_within = "10L"
        component2        = "auth0-domain.1"
        component2_within = "10L"
        skip_entropy_lt   = "3.5"

    strings:
        $secret = /(?:(?:[aA][uU][tT][hH]0[_.-]?(?:[cC][lL][iI][eE][nN][tT][_.-]?)?(?:[sS][eE][cC][rR][eE][tT]|[pP][rR][iI][vV][aA][tT][eE]|[kK][eE][yY]|[tT][oO][kK][eE][nN]))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9_-]{64,128})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
