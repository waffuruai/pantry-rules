// betterleaks v1.10.0's aws-amazon-bedrock-api-key-long-lived rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_AwsAmazonBedrockApiKeyLongLived
{
    meta:
        description     = "Identified a pattern that may indicate long-lived Amazon Bedrock API keys, risking unauthorized Amazon Bedrock usage"
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "AwsAmazonBedrockApiKeyLongLived"
        severity        = "high"
        score           = 80
        id              = "aws-amazon-bedrock-api-key-long-lived"
        confidence      = "high"
        keyword         = "absk"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b(ABSK[A-Za-z0-9+\/]{109,269}={0,2})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
