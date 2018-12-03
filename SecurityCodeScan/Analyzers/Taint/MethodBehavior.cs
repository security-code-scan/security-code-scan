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

    public class InjectableArgument
    {
        public InjectableArgument(ulong taint, string locale, bool not = false)
        {
            Locale            = locale;
            RequiredTaintBits = taint;
            Not                = not;
        }

        public bool   Not;

        public string Locale { get; }

        public ulong RequiredTaintBits { get; }
    }

    public class MethodBehavior
    {
        public IReadOnlyDictionary<int, InjectableArgument> InjectableArguments { get; }
        public IReadOnlyList<Condition>                     Conditions          { get; }
        public IReadOnlyDictionary<int, PostCondition>      PostConditions      { get; }
        public InjectableArgument                           InjectableField     { get; }

        private readonly InjectableArgument NotInjectableArgument = new InjectableArgument(0ul, null);

        public MethodBehavior(IReadOnlyList<Condition>                     preConditions,
                              IReadOnlyDictionary<int, PostCondition>      postConditions,
                              IReadOnlyDictionary<int, InjectableArgument> injectableArguments,
                              InjectableArgument                           injectableField)
        {
            InjectableArguments = injectableArguments ?? EmptyDictionary<int, InjectableArgument>.Value;
            PostConditions      = postConditions      ?? EmptyDictionary<int, PostCondition>.Value;
            Conditions          = preConditions       ?? EmptyList<Condition>.Value;
            InjectableField     = injectableField     ?? NotInjectableArgument;
        }
    }
}
