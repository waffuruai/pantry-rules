// betterleaks v1.10.0's slack-user-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_SlackUserToken
{
    meta:
        description     = "Found a Slack User token, posing a risk of unauthorized user impersonation and data access within Slack workspaces."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SlackUserToken"
        severity        = "high"
        score           = 80
        id              = "slack-user-token"
        confidence      = "high"
        keyword         = "xoxp-"
        keyword         = "xoxe-"
        skip_entropy_le = "2.0"

    strings:
        $secret = /xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}/  // gitleaks:allow

    condition:
        $secret
}
