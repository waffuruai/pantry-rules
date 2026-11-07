// betterleaks v1.10.0's aws-secret-access-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_AwsSecretAccessKey
{
    meta:
        description     = "Identified an AWS secret access key, used as a component of the aws-access-token composite rule."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "AwsSecretAccessKey"
        severity        = "medium"
        score           = 50
        id              = "aws-secret-access-key"
        confidence      = "medium"
        keyword         = "secret"
        keyword         = "access"
        keyword         = "key"
        keyword         = "token"
        skip_entropy_le = "4.0"

    strings:
        $secret = /(?:(?:[sS][eE][cC][rR][eE][tT]|[aA][cC][cC][eE][sS][sS]|[kK][eE][yY]|[tT][oO][kK][eE][nN])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Za-z0-9\/+=]{40})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
