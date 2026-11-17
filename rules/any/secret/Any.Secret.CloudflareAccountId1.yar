// betterleaks v1.10.0's cloudflare-account-id.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_CloudflareAccountId1
{
    meta:
        description = "Detected a Cloudflare account ID, used as a component of Cloudflare API key validation."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "CloudflareAccountId1"
        severity    = "high"
        score       = 80
        id          = "cloudflare-account-id.1"
        confidence  = "high"
        keyword     = "account_id"
        keyword     = "account-id"
        keyword     = "account id"
        keyword     = "accountid"

    strings:
        $secret = /(?:(?:[aA][cC][cC][oO][uU][nN][tT][_. -]*[iI][dD])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
