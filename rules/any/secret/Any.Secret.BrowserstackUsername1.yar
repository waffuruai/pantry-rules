// betterleaks v1.10.0's browserstack-username.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_BrowserstackUsername1
{
    meta:
        description     = "BrowserStack username, used as a component of the BrowserStack access-key composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "BrowserstackUsername1"
        severity        = "medium"
        score           = 50
        id              = "browserstack-username.1"
        confidence      = "medium"
        keyword         = "browserstack"
        skip_entropy_lt = "2.0"

    strings:
        $secret = /(?:(?:[bB][rR][oO][wW][sS][eE][rR][sS][tT][aA][cC][kK][_.-]?(?:[uU][sS][eE][rR][nN][aA][mM][eE]|[uU][sS][eE][rR]))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9][A-Za-z0-9._-]{2,39})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
