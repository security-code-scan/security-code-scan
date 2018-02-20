namespace SecurityCodeScan.Analyzers.Taint
{
    public enum VariableTag
    {
        // HttpCookie
        HttpCookieSecure,
        HttpCookieHttpOnly,

        // PasswordValidator
        RequiredLengthIsSet,
        RequireDigitIsSet,
        RequireLowercaseIsSet,
        RequireNonLetterOrDigitIsSet,
        RequireUppercaseIsSet
    }
}
