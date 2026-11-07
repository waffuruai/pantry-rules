// betterleaks v1.10.0's browserstack-access-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_BrowserstackAccessKey1
{
    meta:
        description       = "BrowserStack access key, which may allow access to automated browser and device testing when paired with its username."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "BrowserstackAccessKey1"
        severity          = "high"
        score             = 80
        id                = "browserstack-access-key.1"
        confidence        = "high"
        keyword           = "browserstack"
        component1        = "browserstack-username.1"
        component1_within = "5L"
        skip_entropy_lt   = "3.0"

    strings:
        $secret = /(?:(?:[bB][rR][oO][wW][sS][eE][rR][sS][tT][aA][cC][kK][_.-]?(?:[aA][cC][cC][eE][sS][sS][_.-]?)?(?:[kK][eE][yY]|[sS][eE][cC][rR][eE][tT]|[tT][oO][kK][eE][nN]))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9]{20})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
