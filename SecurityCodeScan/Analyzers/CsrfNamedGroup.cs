using System.Collections.Generic;
using System.Linq;

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

        public readonly Dictionary<string, List<CsrfAttributeCondition>> NonActionAttributes;
        public readonly Dictionary<string, List<CsrfAttributeCondition>> AnonymousAttributes;
        public readonly Dictionary<string, List<CsrfAttributeCondition>> VulnerableAttributes;
        public readonly Dictionary<string, List<CsrfAttributeCondition>> IgnoreAttributes;
        public readonly Dictionary<string, List<CsrfAttributeCondition>> AntiCsrfAttributes;
        public readonly Dictionary<string, List<CsrfAttributeCondition>> ActionAttributes;

        public CsrfNamedGroup(string name)
        {
            Name = name;

            Controllers = new HashSet<string>();
            NonActionAttributes = new Dictionary<string, List<CsrfAttributeCondition>>();
            AnonymousAttributes = new Dictionary<string, List<CsrfAttributeCondition>>();
            VulnerableAttributes = new Dictionary<string, List<CsrfAttributeCondition>>();
            IgnoreAttributes = new Dictionary<string, List<CsrfAttributeCondition>>();
            AntiCsrfAttributes = new Dictionary<string, List<CsrfAttributeCondition>>();
            ActionAttributes = new Dictionary<string, List<CsrfAttributeCondition>>();
        }
    }
}
