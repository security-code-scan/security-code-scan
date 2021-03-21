#nullable disable
using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Config
{
    internal class AttributeCondition
    {
        private static readonly AttributeCondition TRUE = new AttributeCondition();

        public static readonly object NONE = new object();

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
                if (!destination.TryGetValue(attr.Type, out var conditions))
                {
                    destination[attr.Type] = conditions = new List<AttributeCondition>();
                }

                if (attr.Condition == null)
                {
                    conditions.Add(AttributeCondition.TRUE);
                    continue;
                }

                foreach (var c in attr.Condition)
                {
                    var condition = CreateAttributeCondition(c);
                    conditions.Add(condition);
                }
            }
        }

        private static AttributeCondition CreateAttributeCondition(Dictionary<object, object> conditions)
        {
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

                if (conditionValue == "none")
                    ret.MustMatch.Add((key, NONE));
                else if (int.TryParse(conditionValue, out var intVal))
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

    internal class MethodAttributes : IncludeExcludeAttributes
    {
        public MethodAttributes(Method method)
        {
            IncludeConstructor = method.IncludeConstructor;

            Static = method.Static;

            Accessibility = method.Accessibility;

            AttributeCondition.AddAttributes(Include, method?.Attributes?.Include);
            AttributeCondition.AddAttributes(Exclude, method?.Attributes?.Exclude);
        }

        public HashSet<Accessibility> Accessibility { get; }

        public bool? IncludeConstructor { get; }

        public bool? Static { get; }
    }

    internal class ParameterAttributes : IncludeExcludeAttributes
    {
        public ParameterAttributes(Parameter parameter)
        {
            AttributeCondition.AddAttributes(Include, parameter?.Attributes?.Include);
            AttributeCondition.AddAttributes(Exclude, parameter?.Attributes?.Exclude);
        }
    }

    internal class AttributeController : IncludeExcludeAttributes
    {
        public AttributeController(Class @class)
        {
            Parent = @class.Parent;

            Suffix = @class.Suffix;

            Accessibility = @class.Accessibility;

            AttributeCondition.AddAttributes(Include, @class?.Attributes?.Include);
            AttributeCondition.AddAttributes(Exclude, @class?.Attributes?.Exclude);
        }

        public Suffix Suffix { get; }

        public HashSet<Accessibility> Accessibility { get; }

        private string _Parent;

        public string Parent
        {
            get => _Parent;
            set
                {
                if (_Parent != null)
                    throw new Exception("Parent class is already defined.");

                _Parent = value;
                }
        }
    }

    internal class NamedGroup
    {
        public readonly string Name;

        public ReadOnlyHashSet<string> Dependency { get; }
        private readonly HashSet<string> _Dependency;

        public readonly DiagnosticDescriptor Message;
        public readonly Dictionary<string, List<AttributeCondition>> IncludedRequiredAttributes = new Dictionary<string, List<AttributeCondition>>();
        public readonly Dictionary<string, List<AttributeCondition>> ExcludedRequiredAttributes = new Dictionary<string, List<AttributeCondition>>();

        public AttributeController Class { get; private set; }

        public MethodAttributes Method { get; private set; }

        public ParameterAttributes Parameter { get; private set; }

        public NamedGroup(AttributeCheck configData, string diagnosticId)
        {
            Name = configData.Name;

            if (configData.Dependency != null)
            {
                _Dependency = configData.Dependency;
                Dependency = new ReadOnlyHashSet<string>(_Dependency);
            }

            if (configData.Message != null)
                Message = LocaleUtil.GetDescriptorByText(diagnosticId, configData.Message.Title, configData.Message.Description);

            AttributeCondition.AddAttributes(IncludedRequiredAttributes, configData.RequiredAttributes?.Include);
            AttributeCondition.AddAttributes(ExcludedRequiredAttributes, configData.RequiredAttributes?.Exclude);

            if (configData.Class != null)
                Class = new AttributeController(configData.Class);

            if (configData.Method != null)
                Method = new MethodAttributes(configData.Method);

            if (configData.Parameter != null)
                Parameter = new ParameterAttributes(configData.Parameter);
        }

        public void AddFrom(AttributeCheck configData)
        {
            AttributeCondition.AddAttributes(IncludedRequiredAttributes, configData.RequiredAttributes?.Include);
            AttributeCondition.AddAttributes(ExcludedRequiredAttributes, configData.RequiredAttributes?.Exclude);

            if (configData.Class?.Parent != null)
            {
                Class.Parent = configData.Class.Parent;
            }

            if (Class == null)
            {
                if (configData.Class != null)
                    Class = new AttributeController(configData.Class);
            }
            else
            {
                AttributeCondition.AddAttributes(Class.Include, configData.Class?.Attributes?.Include);
                AttributeCondition.AddAttributes(Class.Exclude, configData.Class?.Attributes?.Exclude);
            }

            if (Method == null)
            {
                if (configData.Method != null)
                    Method = new MethodAttributes(configData.Method);
            }
            else
            {
                AttributeCondition.AddAttributes(Method.Include, configData.Method?.Attributes?.Include);
                AttributeCondition.AddAttributes(Method.Exclude, configData.Method?.Attributes?.Exclude);
            }

            if (Parameter == null)
            {
                if (configData.Parameter != null)
                    Parameter = new ParameterAttributes(configData.Parameter);
            }
            else
            {
                AttributeCondition.AddAttributes(Parameter.Include, configData.Parameter?.Attributes?.Include);
                AttributeCondition.AddAttributes(Parameter.Exclude, configData.Parameter?.Attributes?.Exclude);
            }
        }
    }
}
