namespace SecurityCodeScan.Analyzers.Taint
{
    public enum VariableTag
    {
        // HttpCookie
        HttpCookie,
        HttpCookieSecure,
        HttpCookieHttpOnly,

        // PasswordValidator
        PasswordValidator,
        RequiredLengthIsSet,
        RequireDigitIsSet,
        RequireLowercaseIsSet,
        RequireNonLetterOrDigitIsSet,
        RequireUppercaseIsSet
    }
}
