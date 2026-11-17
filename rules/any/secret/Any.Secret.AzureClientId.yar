// betterleaks v1.10.0's azure-client-id rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_AzureClientId
{
    meta:
        description     = "Detected an Azure client ID, used as a component of Azure service principal validation."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "AzureClientId"
        severity        = "medium"
        score           = 50
        id              = "azure-client-id"
        confidence      = "medium"
        keyword         = "client"
        skip_entropy_le = "2.5"

    strings:
        $secret = /\b(?:[cC][lL][iI][eE][nN][tT][_\s.-]*[iI][dD]|[Aa][Zz][Uu][Rr][Ee]_[Cc][Ll][Ii][Ee][Nn][Tt]_[Ii][Dd])\b(?:.{0,24}?)([A-F0-9a-f]{8}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{12})\b/  // gitleaks:allow

    condition:
        $secret
}
