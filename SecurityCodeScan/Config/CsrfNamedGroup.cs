using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Locale;

namespace SecurityCodeScan.Config
{
    internal class CsrfAttributeCondition
    {
        public static readonly CsrfAttributeCondition TRUE = new CsrfAttributeCondition();

        public struct Pair
        {
            public Pair(object parameterIndexOrPropertyName, object expectedValue)
            {
                ParameterIndexOrPropertyName = parameterIndexOrPropertyName;
                ExpectedValue = expectedValue;
            }

            public readonly object ParameterIndexOrPropertyName;
            public readonly object ExpectedValue;
        }

        public readonly List<Pair> MustMatch;

        public CsrfAttributeCondition()
        {
            MustMatch = new List<Pair>();
        }

        public static void AddCsrfAttributes(Dictionary<string, List<CsrfAttributeCondition>> destination, IEnumerable<CsrfAttributeData> source)
        {
            if (source == null)
                return;

            foreach (var attr in source)
            {
                var condition = CreateCsrfAttributeCondition(attr.Condition);

                if (!destination.TryGetValue(attr.Name, out var conditions))
                {
                    destination[attr.Name] = conditions = new List<CsrfAttributeCondition>();
                }

                conditions.Add(condition);
            }
        }

        private static CsrfAttributeCondition CreateCsrfAttributeCondition(Dictionary<object, object> conditions)
        {
            if (conditions == null)
                return CsrfAttributeCondition.TRUE;

            var ret = new CsrfAttributeCondition();

            foreach (var argument in conditions)
            {
                if (!(argument.Value is Dictionary<object, object> d))
                    throw new Exception("Invalid condition format, expected dictionary");

                if (d.Count != 1)
                    throw new Exception("Only one condition per argument is supported");

                if (!(argument.Key is string arg))
                    throw new Exception("Invalid condition format, expected string");

                int? idx;

                if (int.TryParse(arg, out var parsedArg))
                {
                    if (parsedArg < 0)
                    {
                        throw new Exception("Ordinal condition keys must be non-negative integers");
                    }

                    idx = parsedArg;
                }
                else
                {
                    idx = null;
                }

                var condition = d.Single();
                if (!(condition.Key is string valueKey) || valueKey != "Value")
                    throw new Exception("Only 'Value' conditions are supported");

                if (!(condition.Value is string conditionValue))
                    throw new Exception("Invalid condition format, expected a string");

                object key = idx != null ? (object)idx.Value : arg;

                if (int.TryParse(conditionValue, out var intVal))
                    ret.MustMatch.Add(new CsrfAttributeCondition.Pair(key, intVal));
                else if (bool.TryParse(conditionValue, out var boolVal))
                    ret.MustMatch.Add(new CsrfAttributeCondition.Pair(key, boolVal));
                else
                    ret.MustMatch.Add(new CsrfAttributeCondition.Pair(key, conditionValue));
            }

            return ret;
        }
    }

    internal class IncludeExcludeAttributes
    {
        public IncludeExcludeAttributes()
        {
            Include = new Dictionary<string, List<CsrfAttributeCondition>>();
            Exclude = new Dictionary<string, List<CsrfAttributeCondition>>();
        }

        public Dictionary<string, List<CsrfAttributeCondition>> Include { get; }

        public Dictionary<string, List<CsrfAttributeCondition>> Exclude { get; }
    }

    internal class CsrfController : IncludeExcludeAttributes
    {
        public CsrfController(CsrfClass @class)
        {
            if (@class.Name != null)
                Names = new HashSet<string>(@class.Name);

            CsrfAttributeCondition.AddCsrfAttributes(Include, @class?.Attributes?.Include);
            CsrfAttributeCondition.AddCsrfAttributes(Exclude, @class?.Attributes?.Exclude);
        }

        public readonly HashSet<string> Names;
    }

    internal class CsrfNamedGroup
    {
        public readonly string Name;

        public readonly DiagnosticDescriptor Message;
        public readonly Dictionary<string, List<CsrfAttributeCondition>> AntiCsrfAttributes = new Dictionary<string, List<CsrfAttributeCondition>>();

        private CsrfController _Class;
        public CsrfController Class => _Class;

        private IncludeExcludeAttributes _Method = new IncludeExcludeAttributes();
        public IncludeExcludeAttributes Method => _Method;

        private IncludeExcludeAttributes _Parameter = new IncludeExcludeAttributes();
        public IncludeExcludeAttributes Parameter => _Parameter;

        public CsrfNamedGroup(CsrfProtectionData configData)
        {
            Name = configData.Name;

            if (configData.Message != null)
                Message = LocaleUtil.GetDescriptorByText(CsrfTokenDiagnosticAnalyzer.DiagnosticId, configData.Message.Title, configData.Message.Description);

            CsrfAttributeCondition.AddCsrfAttributes(AntiCsrfAttributes, configData.AntiCsrfAttributes);

            if (configData.Class != null)
                _Class = new CsrfController(configData.Class);

            CsrfAttributeCondition.AddCsrfAttributes(Method.Include, configData.Method?.Attributes.Include);
            CsrfAttributeCondition.AddCsrfAttributes(Method.Exclude, configData.Method?.Attributes.Exclude);
            CsrfAttributeCondition.AddCsrfAttributes(Parameter.Include, configData.Parameter?.Attributes.Include);
            CsrfAttributeCondition.AddCsrfAttributes(Parameter.Exclude, configData.Parameter?.Attributes.Exclude);
        }

        public void AddFrom(CsrfProtectionData configData)
        {
            CsrfAttributeCondition.AddCsrfAttributes(AntiCsrfAttributes, configData.AntiCsrfAttributes);

            if (configData.Class?.Name != null)
            {
                foreach (var name in configData.Class.Name)
                    Class.Names.Add(name);
            }

            CsrfAttributeCondition.AddCsrfAttributes(Class.Include, configData.Class?.Attributes?.Include);
            CsrfAttributeCondition.AddCsrfAttributes(Class.Exclude, configData.Class?.Attributes?.Exclude);

            CsrfAttributeCondition.AddCsrfAttributes(Method.Include, configData.Method?.Attributes?.Include);
            CsrfAttributeCondition.AddCsrfAttributes(Method.Exclude, configData.Method?.Attributes?.Exclude);
            CsrfAttributeCondition.AddCsrfAttributes(Parameter.Include, configData.Parameter?.Attributes?.Include);
            CsrfAttributeCondition.AddCsrfAttributes(Parameter.Exclude, configData.Parameter?.Attributes?.Exclude);
        }
    }
}
