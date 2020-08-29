#nullable disable
using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using SecurityCodeScan.Analyzers.Locale;

namespace SecurityCodeScan.Config
{
    internal class AttributeCondition
    {
        private static readonly AttributeCondition TRUE = new AttributeCondition();

        public readonly List<(object ParameterIndexOrPropertyName, object ExpectedValue)> MustMatch;

        public AttributeCondition()
        {
            MustMatch = new List<(object ParameterIndexOrPropertyName, object ExpectedValue)>();
        }

        public static void AddAttributes(Dictionary<string, List<AttributeCondition>> destination, IEnumerable<AttributeCheckData> source)
        {
            if (source == null)
                return;

            foreach (var attr in source)
            {
                var condition = CreateAttributeCondition(attr.Condition);

                if (!destination.TryGetValue(attr.Name, out var conditions))
                {
                    destination[attr.Name] = conditions = new List<AttributeCondition>();
                }

                conditions.Add(condition);
            }
        }

        private static AttributeCondition CreateAttributeCondition(Dictionary<object, object> conditions)
        {
            if (conditions == null)
                return AttributeCondition.TRUE;

            var ret = new AttributeCondition();

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
                    ret.MustMatch.Add((key, intVal));
                else if (bool.TryParse(conditionValue, out var boolVal))
                    ret.MustMatch.Add((key, boolVal));
                else
                    ret.MustMatch.Add((key, conditionValue));
            }

            return ret;
        }
    }

    internal class IncludeExcludeAttributes
    {
        public IncludeExcludeAttributes()
        {
            Include = new Dictionary<string, List<AttributeCondition>>();
            Exclude = new Dictionary<string, List<AttributeCondition>>();
        }

        public Dictionary<string, List<AttributeCondition>> Include { get; }

        public Dictionary<string, List<AttributeCondition>> Exclude { get; }
    }

    internal class AttributeController : IncludeExcludeAttributes
    {
        public AttributeController(AttributeCheckClass @class)
        {
            if (@class.Name != null)
                Names = new HashSet<string>(@class.Name);

            AttributeCondition.AddAttributes(Include, @class?.Attributes?.Include);
            AttributeCondition.AddAttributes(Exclude, @class?.Attributes?.Exclude);
        }

        public readonly HashSet<string> Names;
    }

    internal class NamedGroup
    {
        public readonly string Name;

        public readonly DiagnosticDescriptor Message;
        public readonly Dictionary<string, List<AttributeCondition>> RequiredAttributes = new Dictionary<string, List<AttributeCondition>>();

        public AttributeController Class { get; }

        public IncludeExcludeAttributes Method { get; } = new IncludeExcludeAttributes();

        public IncludeExcludeAttributes Parameter { get; } = new IncludeExcludeAttributes();

        public NamedGroup(AttributeCheck configData, string diagnosticId)
        {
            Name = configData.Name;

            if (configData.Message != null)
                Message = LocaleUtil.GetDescriptorByText(diagnosticId, configData.Message.Title, configData.Message.Description);

            AttributeCondition.AddAttributes(RequiredAttributes, configData.RequiredAttributes);

            if (configData.Class != null)
                Class = new AttributeController(configData.Class);

            AttributeCondition.AddAttributes(Method.Include, configData.Method?.Attributes.Include);
            AttributeCondition.AddAttributes(Method.Exclude, configData.Method?.Attributes.Exclude);
            AttributeCondition.AddAttributes(Parameter.Include, configData.Parameter?.Attributes.Include);
            AttributeCondition.AddAttributes(Parameter.Exclude, configData.Parameter?.Attributes.Exclude);
        }

        public void AddFrom(AttributeCheck configData)
        {
            AttributeCondition.AddAttributes(RequiredAttributes, configData.RequiredAttributes);

            if (configData.Class?.Name != null)
            {
                foreach (var name in configData.Class.Name)
                    Class.Names.Add(name);
            }

            AttributeCondition.AddAttributes(Class.Include, configData.Class?.Attributes?.Include);
            AttributeCondition.AddAttributes(Class.Exclude, configData.Class?.Attributes?.Exclude);

            AttributeCondition.AddAttributes(Method.Include, configData.Method?.Attributes?.Include);
            AttributeCondition.AddAttributes(Method.Exclude, configData.Method?.Attributes?.Exclude);
            AttributeCondition.AddAttributes(Parameter.Include, configData.Parameter?.Attributes?.Include);
            AttributeCondition.AddAttributes(Parameter.Exclude, configData.Parameter?.Attributes?.Exclude);
        }
    }
}
