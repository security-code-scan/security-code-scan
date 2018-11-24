using System.Collections.Generic;
using System.Collections.Immutable;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Analyzers.Taint
{
    public class PostCondition
    {
        public PostCondition(ulong taint, ImmutableHashSet<int> taintFromArguments = null)
        {
            Taint              = taint;
            TaintFromArguments = taintFromArguments ?? ImmutableHashSet<int>.Empty;
        }

        public ulong Taint { get; }

        public ImmutableHashSet<int> TaintFromArguments { get; }
    }

    public class MethodBehavior
    {
        public IReadOnlyDictionary<int, ulong>         InjectableArguments { get; }
        public ImmutableHashSet<int>                   PasswordArguments   { get; }
        public IReadOnlyDictionary<int, object>        PreConditions       { get; }
        public IReadOnlyDictionary<int, PostCondition> PostConditions      { get; }
        public string                                  LocaleInjection     { get; }
        public ulong                                   InjectableField     { get; }
        public bool                                    IsPasswordField     { get; }

        public MethodBehavior(IReadOnlyDictionary<int, object>        preConditions,
                              IReadOnlyDictionary<int, PostCondition> postConditions,
                              IReadOnlyDictionary<int, ulong>         injectableArguments,
                              ImmutableHashSet<int>                   passwordArguments,
                              string                                  localeInjection,
                              ulong                                   injectableField,
                              bool                                    isPasswordField)
        {
            InjectableArguments = injectableArguments ?? EmptyDictionary<int, ulong>.Value;
            PasswordArguments   = passwordArguments   ?? ImmutableHashSet<int>.Empty;
            PostConditions      = postConditions      ?? EmptyDictionary<int, PostCondition>.Value;
            PreConditions       = preConditions       ?? EmptyDictionary<int, object>.Value;
            LocaleInjection     = localeInjection;
            InjectableField     = injectableField;
            IsPasswordField     = isPasswordField;
        }

        public MethodBehavior(IReadOnlyDictionary<int, PostCondition> postConditions)
        {
            InjectableArguments = EmptyDictionary<int, ulong>.Value;
            PasswordArguments   = ImmutableHashSet<int>.Empty;
            PostConditions      = postConditions ?? EmptyDictionary<int, PostCondition>.Value;
            PreConditions       = EmptyDictionary<int, object>.Value;
            LocaleInjection     = null;
            InjectableField     = 0ul;
            IsPasswordField     = false;
        }
    }
}
