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

    public class Condition
    {
        public Condition(IReadOnlyDictionary<int, object> @if, IReadOnlyDictionary<int, PostCondition> then)
        {
            If = @if;
            Then = then;
        }

        public IReadOnlyDictionary<int, object>        If   { get; }
        public IReadOnlyDictionary<int, PostCondition> Then { get; }
    }

    public class MethodBehavior
    {
        public IReadOnlyDictionary<int, ulong>         InjectableArguments { get; }
        public ImmutableHashSet<int>                   PasswordArguments   { get; }
        public IReadOnlyList<Condition>                Conditions          { get; }
        public IReadOnlyDictionary<int, PostCondition> PostConditions      { get; }
        public string                                  LocaleInjection     { get; }
        public ulong                                   InjectableField     { get; }

        public MethodBehavior(IReadOnlyList<Condition>                preConditions,
                              IReadOnlyDictionary<int, PostCondition> postConditions,
                              IReadOnlyDictionary<int, ulong>         injectableArguments,
                              ImmutableHashSet<int>                   passwordArguments,
                              string                                  localeInjection,
                              ulong                                   injectableField)
        {
            InjectableArguments = injectableArguments ?? EmptyDictionary<int, ulong>.Value;
            PasswordArguments   = passwordArguments   ?? ImmutableHashSet<int>.Empty;
            PostConditions      = postConditions      ?? EmptyDictionary<int, PostCondition>.Value;
            Conditions          = preConditions       ?? EmptyList<Condition>.Value;
            LocaleInjection     = localeInjection;
            InjectableField     = injectableField;
        }
    }
}
