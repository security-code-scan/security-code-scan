using System.Collections.Immutable;
using System.Collections.ObjectModel;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Analyzers.Taint
{
    public class MethodBehavior
    {
        public ReadOnlyDictionary<int, ulong> InjectableArguments { get; }
        public ImmutableHashSet<int>          PasswordArguments   { get; }
        public ReadOnlyDictionary<int, ulong> TaintFromArguments  { get; }
        public ReadOnlyDictionary<int, object> PreConditions      { get; }
        public ReadOnlyDictionary<int, ulong> PostConditions      { get; }
        public string                         LocaleInjection     { get; }
        public string                         LocalePassword      { get; }
        public ulong                          InjectableField     { get; }
        public bool                           IsPasswordField     { get; }

        public MethodBehavior(ReadOnlyDictionary<int, ulong>  injectableArguments,
                              ImmutableHashSet<int>           passwordArguments,
                              ReadOnlyDictionary<int, ulong>  taintFromArguments,
                              ReadOnlyDictionary<int, object> preConditions,
                              ReadOnlyDictionary<int, ulong>  postConditions,
                              string                          localeInjection,
                              string                          localePassword,
                              ulong                           injectableField,
                              bool                            isPasswordField)
        {
            InjectableArguments  = injectableArguments ?? EmptyDictionary<int, ulong>.Value;
            PasswordArguments    = passwordArguments   ?? ImmutableHashSet<int>.Empty;
            TaintFromArguments   = taintFromArguments  ?? EmptyDictionary<int, ulong>.Value;
            PostConditions       = postConditions      ?? EmptyDictionary<int, ulong>.Value;
            PreConditions        = preConditions       ?? EmptyDictionary<int, object>.Value;
            LocaleInjection      = localeInjection;
            LocalePassword       = localePassword;
            InjectableField      = injectableField;
            IsPasswordField      = isPasswordField;
        }
    }
}
