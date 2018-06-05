namespace SecurityCodeScan.Analyzers.Taint
{
    public class MethodBehavior
    {
        public int[]  InjectablesArguments { get; }
        public int[]  PasswordArguments    { get; }
        public int[]  TaintFromArguments   { get; }
        public string LocaleInjection      { get; }
        public string LocalePassword       { get; }
        public bool   IsInjectableField    { get; }
        public bool   IsPasswordField      { get; }

        public MethodBehavior(int[] injectablesArguments,
                              int[] passwordArguments,
                              int[] taintFromArguments,
                              string localeInjection,
                              string localePassword,
                              bool isInjectableField,
                              bool isPasswordField)
        {
            InjectablesArguments = injectablesArguments ?? EmptyArray<int>.Value;
            PasswordArguments    = passwordArguments ?? EmptyArray<int>.Value;
            TaintFromArguments   = taintFromArguments ?? EmptyArray<int>.Value;
            LocaleInjection      = localeInjection;
            LocalePassword       = localePassword;
            IsInjectableField    = isInjectableField;
            IsPasswordField      = isPasswordField;
        }
    }
}
