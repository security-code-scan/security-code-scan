using System.Collections.Generic;

namespace SecurityCodeScan.Analyzers
{
    internal class CsrfAttributeCondition
    {
        public static readonly CsrfAttributeCondition TRUE = new CsrfAttributeCondition();

        public readonly List<(object ParameterIndexOrPropertyName, object ExpectedValue)> MustMatch;

        public CsrfAttributeCondition()
        {
            MustMatch = new List<(object ParameterIndexOrPropertyName, object ExpectedValue)>();
        }
    }

    internal class CsrfNamedGroup
    {
        public readonly string Name;

        public readonly HashSet<string> Controllers;

        public readonly List<(string AttributeName, CsrfAttributeCondition Condition)> NonActionAttributes;
        public readonly List<(string AttributeName, CsrfAttributeCondition Condition)> AnonymousAttributes;
        public readonly List<(string AttributeName, CsrfAttributeCondition Condition)> HttpMethodAttributes;
        public readonly List<(string AttributeName, CsrfAttributeCondition Condition)> IgnoreAttributes;
        public readonly List<(string AttributeName, CsrfAttributeCondition Condition)> AntiCsrfAttributes;
        public readonly List<(string AttributeName, CsrfAttributeCondition Condition)> ActionAttributes;

        public CsrfNamedGroup(string name)
        {
            Name = name;

            Controllers = new HashSet<string>();
            NonActionAttributes = new List<(string AttributeName, CsrfAttributeCondition Condition)>();
            AnonymousAttributes = new List<(string AttributeName, CsrfAttributeCondition Condition)>();
            HttpMethodAttributes = new List<(string AttributeName, CsrfAttributeCondition Condition)>();
            IgnoreAttributes = new List<(string AttributeName, CsrfAttributeCondition Condition)>();
            AntiCsrfAttributes = new List<(string AttributeName, CsrfAttributeCondition Condition)>();
            ActionAttributes = new List<(string AttributeName, CsrfAttributeCondition Condition)>();
        }
    }
}
