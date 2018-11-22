using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using SecurityCodeScan.Analyzers.Taint;

namespace SecurityCodeScan.Config
{
    /// <summary>
    /// Internal configuration optimized for queries
    /// </summary>
    internal class Configuration
    {
        public Configuration()
        {
            PasswordValidatorRequiredProperties = new HashSet<string>();
            Behavior                            = new Dictionary<string, KeyValuePair<string, MethodBehavior>>();
            Sinks                               = new Dictionary<string, KeyValuePair<string, MethodBehavior>>();
            Sources                             = new HashSet<string>();
            AntiCsrfAttributes                  = new Dictionary<string, List<string>>();
            PasswordFields                      = new HashSet<string>();
            ConstantFields                      = new HashSet<string>();
            SanitizerTypeNameToBit              = new Dictionary<string, ulong>(62);
        }

        public Configuration(Configuration config)
        {
            AuditMode                           = config.AuditMode;
            PasswordValidatorRequiredLength     = config.PasswordValidatorRequiredLength;
            MinimumPasswordValidatorProperties  = config.MinimumPasswordValidatorProperties;
            PasswordValidatorRequiredProperties = new HashSet<string>(config.PasswordValidatorRequiredProperties);
            Behavior                            = new Dictionary<string, KeyValuePair<string, MethodBehavior>>(config.Behavior);
            Sinks                               = new Dictionary<string, KeyValuePair<string, MethodBehavior>>(config.Sinks);
            Sources                             = new HashSet<string>(config.Sources);
            AntiCsrfAttributes                  = new Dictionary<string, List<string>>(config.AntiCsrfAttributes);
            PasswordFields                      = new HashSet<string>(config.PasswordFields);
            ConstantFields                      = new HashSet<string>(config.ConstantFields);
            SanitizerTypeNameToBit              = new Dictionary<string, ulong>(config.SanitizerTypeNameToBit);
        }

        public Configuration(ConfigData configData) : this()
        {
            if (configData.SanitizerTypes != null)
                RegisterSanitizerTypes(configData.SanitizerTypes);

            AuditMode                          = configData.AuditMode                          ?? false;
            MinimumPasswordValidatorProperties = configData.MinimumPasswordValidatorProperties ?? 0;
            PasswordValidatorRequiredLength    = configData.PasswordValidatorRequiredLength    ?? 0;

            if (configData.PasswordValidatorRequiredProperties != null)
            {
                foreach (var data in configData.PasswordValidatorRequiredProperties)
                {
                    PasswordValidatorRequiredProperties.Add(data);
                }
            }

            foreach (var data in configData.Behavior)
            {
                Behavior[data.Key] = CreateBehavior(data.Value);
            }

            foreach (var data in configData.Sinks)
            {
                Sinks[data.Key] = CreateBehavior(data.Value);
            }

            foreach (var source in configData.Sources)
            {
                if (source.Value.FromExternalParameters)
                {
                    Sources.Add(string.IsNullOrEmpty(source.Value.Namespace)
                                    ? source.Value.ClassName
                                    : $"{source.Value.Namespace}.{source.Value.ClassName}");
                }
                else
                {
                    Behavior[source.Key] = CreateBehavior(source.Value);
                }
            }

            foreach (var data in configData.CsrfProtectionAttributes)
            {
                AddAntiCsrfTAttributeToConfiguration(data);
            }

            foreach (var data in configData.PasswordFields)
            {
                PasswordFields.Add(data.ToUpperInvariant());
            }

            foreach (var data in configData.ConstantFields)
            {
                ConstantFields.Add(data);
            }
        }

        public bool                                                     AuditMode;
        public int                                                      PasswordValidatorRequiredLength;
        public int                                                      MinimumPasswordValidatorProperties;
        public HashSet<string>                                          PasswordValidatorRequiredProperties;
        public Dictionary<string, KeyValuePair<string, MethodBehavior>> Behavior;
        public Dictionary<string, KeyValuePair<string, MethodBehavior>> Sinks;
        public HashSet<string>                                          Sources;
        public Dictionary<string, List<string>>                         AntiCsrfAttributes;
        public HashSet<string>                                          PasswordFields;
        public HashSet<string>                                          ConstantFields;
        public Dictionary<string, ulong>                                SanitizerTypeNameToBit;

        public void MergeWith(ConfigData config)
        {
            if (config.SanitizerTypes != null)
                RegisterSanitizerTypes(config.SanitizerTypes);

            if (config.AuditMode.HasValue)
                AuditMode = config.AuditMode.Value;

            if (config.MinimumPasswordValidatorProperties.HasValue)
                MinimumPasswordValidatorProperties = config.MinimumPasswordValidatorProperties.Value;

            if (config.PasswordValidatorRequiredLength.HasValue)
                PasswordValidatorRequiredLength = config.PasswordValidatorRequiredLength.Value;

            if (config.PasswordValidatorRequiredProperties != null)
            {
                foreach (var property in config.PasswordValidatorRequiredProperties)
                {
                    PasswordValidatorRequiredProperties.Add(property);
                }
            }

            if (config.Behavior != null)
            {
                foreach (var behavior in config.Behavior)
                {
                    if (behavior.Value == default(MethodBehaviorData))
                        Behavior.Remove(behavior.Key);
                    else
                        Behavior[behavior.Key] = CreateBehavior(behavior.Value);
                }
            }

            if (config.Sinks != null)
            {
                foreach (var sink in config.Sinks)
                {
                    if (sink.Value == default(SinkData))
                        Sinks.Remove(sink.Key);
                    else
                        Sinks[sink.Key] = CreateBehavior(sink.Value);
                }
            }

            if (config.Sources != null)
            {
                foreach (var source in config.Sources)
                {
                    if (source.Value == default(TaintSourceData))
                    {
                        if (Behavior.ContainsKey(source.Key))
                            Behavior.Remove(source.Key);
                        else
                            Sources.Remove(source.Key);
                    }
                    else
                    {
                        if (source.Value.FromExternalParameters)
                        {
                            Sources.Add(string.IsNullOrEmpty(source.Value.Namespace)
                                            ? source.Value.ClassName
                                            : $"{source.Value.Namespace}.{source.Value.ClassName}");
                        }
                        else
                        {
                            Behavior[source.Key] = CreateBehavior(source.Value);
                        }
                    }
                }
            }

            if (config.CsrfProtectionAttributes != null)
            {
                foreach (var data in config.CsrfProtectionAttributes)
                {
                    AddAntiCsrfTAttributeToConfiguration(data);
                }
            }

            if (config.PasswordFields != null)
            {
                foreach (var field in config.PasswordFields)
                {
                    PasswordFields.Add(field.ToUpperInvariant());
                }
            }

            if (config.ConstantFields != null)
            {
                foreach (var field in config.ConstantFields)
                {
                    ConstantFields.Add(field);
                }
            }
        }

        private void RegisterSanitizerTypes(List<string> typeNames)
        {
            var availableBit = 1ul << 3;
            foreach (var registeredBit in SanitizerTypeNameToBit.Values)
            {
                if (availableBit <= registeredBit)
                    availableBit = registeredBit;
            }

            foreach (var typeName in typeNames)
            {
                if (SanitizerTypeNameToBit.ContainsKey(typeName))
                    throw new Exception("Duplicate sanitizer type");

                if (availableBit == 0ul)
                    throw new Exception("Max number of sanitizer types reached");

                SanitizerTypeNameToBit[typeName] = availableBit;
                availableBit                     = availableBit << 1;
            }
        }

        private IReadOnlyDictionary<int, object> GetPreConditions(IReadOnlyDictionary<object, object> arguments)
        {
            if (arguments == null || !arguments.Any())
                return null;

            var conditions = new Dictionary<int, object>(arguments.Count);
            foreach (var argument in arguments)
            {
                if (!(argument.Value is Dictionary<object, object> d))
                    throw new Exception("Invalid precondition format");

                var idx = int.Parse((string)argument.Key);
                if (d.Count != 1)
                    throw new Exception("Only one precondition per argument is supported");

                var condition = d.First();
                if ((string)condition.Key != "Value")
                    throw new Exception("Only 'Value' preconditions are supported");

                var value = (string)condition.Value;
                if (int.TryParse(value, out var intVal))
                    conditions.Add(idx, intVal);
                else
                    conditions.Add(idx, value);
            }

            return conditions;
        }

        private ulong GetSanitizerBits(IEnumerable<object> sanitizerTypes)
        {
            ulong bits = 0ul;
            foreach (var type in sanitizerTypes)
            {
                bits |= SanitizerTypeNameToBit[(string)type];
            }

            if (bits == 0ul)
                throw new Exception("Unknown sanitizer type");

            return bits;
        }

        private IReadOnlyDictionary<int, ulong> GetArguments(IReadOnlyList<object> arguments)
        {
            if (arguments == null || !arguments.Any())
                return null;

            var outArguments = new Dictionary<int, ulong>(arguments.Count);
            foreach (var argument in arguments)
            {
                switch (argument)
                {
                    case string s:
                        outArguments.Add(int.Parse(s), (ulong)VariableTaint.Safe);
                        break;
                    case Dictionary<object, object> d when d.Count == 1:
                    {
                        var indexToTaintType = d.First();
                        switch (indexToTaintType.Value)
                        {
                            case string sanitizerType:
                            {
                                var   i = int.Parse((string)indexToTaintType.Key);
                                ulong sanitizerBit;
                                if (i == -1 && sanitizerType == "Tainted")
                                    sanitizerBit = (ulong)VariableTaint.Tainted;
                                else
                                    sanitizerBit = SanitizerTypeNameToBit[sanitizerType];

                                outArguments.Add(i, sanitizerBit);
                                break;
                            }
                            case List<object> sanitizerTypes:
                            {
                                ulong bits = GetSanitizerBits(sanitizerTypes);
                                outArguments.Add(int.Parse((string)indexToTaintType.Key), bits);
                                break;
                            }
                            default:
                                throw new Exception("Unknown sanitizer type");
                        }

                        break;
                    }
                    default:
                        throw new Exception("Unknown behavior argument");
                }
            }

            return outArguments;
        }

        private readonly ImmutableHashSet<int> NoTaintFromArguments = new HashSet<int> { -1 }.ToImmutableHashSet();

        private IReadOnlyDictionary<int, PostCondition> GetPostConditions(IReadOnlyDictionary<object, object> arguments)
        {
            if (arguments == null || !arguments.Any())
                return null;

            var conditions = new Dictionary<int, PostCondition>(arguments.Count);
            foreach (var argument in arguments)
            {
                if (!(argument.Value is Dictionary<object, object> d))
                    throw new Exception("Invalid postcondition format");

                var                   argKey             = (string)argument.Key;
                var                   idx                = argKey == "Returns" ? -1 : int.Parse(argKey);
                ulong                 sanitizerBit       = 0ul;
                ImmutableHashSet<int> taintFromArguments = null;

                foreach (var condition in d)
                {
                    var conditionKey = (string)condition.Key;
                    switch (conditionKey)
                    {
                        case "Sanitizer":
                            switch (condition.Value)
                            {
                                case string sanitizerType when sanitizerType == "Tainted":
                                    sanitizerBit = (ulong)VariableTaint.Tainted;
                                    break;
                                case string sanitizerType:
                                    sanitizerBit = SanitizerTypeNameToBit[sanitizerType];
                                    break;
                                case List<object> sanitizerTypes:
                                {
                                    foreach (var type in sanitizerTypes)
                                    {
                                        sanitizerBit |= SanitizerTypeNameToBit[(string)type];
                                    }

                                    break;
                                }
                            }

                            break;
                        case "TaintFromArguments":
                            var taintFrom = (List<object>)condition.Value;
                            if (taintFrom != null && taintFrom.Count == 0)
                            {
                                taintFromArguments = NoTaintFromArguments;
                                break;
                            }

                            var args = GetArguments(taintFrom);
                            if (args.Values.Any(x => x != (ulong)VariableTaint.Safe))
                                throw new Exception("'TaintFromArguments' supports only array of indices");

                            taintFromArguments = args.Keys.ToImmutableHashSet();
                            break;
                        default:
                            throw new Exception("Only 'Sanitizer' and 'TaintFromArguments' are supported in postconditions");
                    }
                }

                conditions.Add(idx, new PostCondition(sanitizerBit, taintFromArguments));
            }

            return conditions;
        }

        private ulong GetField(object value)
        {
            if (value == null)
                return 0ul;

            switch (value)
            {
                case string s when s == "true":
                    return (ulong)VariableTaint.Safe;
                case string s:
                    return SanitizerTypeNameToBit[s];
                case List <object> sanitizerTypes: {
                    return GetSanitizerBits(sanitizerTypes);
                }
                default:
                    throw new Exception("Unknown injectable argument");
            }
        }

        private readonly IReadOnlyDictionary<int, PostCondition> TaintSourceReturnArgument = new Dictionary<int, PostCondition>(1)
        {
            {-1, new PostCondition((ulong)VariableTaint.Tainted)}
        };

        private KeyValuePair<string, MethodBehavior> CreateBehavior(TaintSourceData behavior)
        {
            var key = MethodBehaviorHelper.GetMethodBehaviorKey(behavior.Namespace, behavior.ClassName, behavior.Name, behavior.ArgTypes);

            return new KeyValuePair<string, MethodBehavior>(key, new MethodBehavior(TaintSourceReturnArgument));
        }

        private KeyValuePair<string, MethodBehavior> CreateBehavior(MethodBehaviorData behavior)
        {
            var key = MethodBehaviorHelper.GetMethodBehaviorKey(behavior.Namespace, behavior.ClassName, behavior.Name, behavior.ArgTypes);

            return new KeyValuePair<string, MethodBehavior>(key, new MethodBehavior(GetPreConditions(behavior.PreConditions),
                                                                                    GetPostConditions(behavior.PostConditions)));
        }

        private KeyValuePair<string, MethodBehavior> CreateBehavior(SinkData behavior)
        {
            var key = MethodBehaviorHelper.GetMethodBehaviorKey(behavior.Namespace, behavior.ClassName, behavior.Name, behavior.ArgTypes);

            return new KeyValuePair<string, MethodBehavior>(key, new MethodBehavior(GetArguments(behavior.InjectableArguments),
                                                                                    behavior.PasswordArguments?.ToImmutableHashSet(),
                                                                                    behavior.Locale,
                                                                                    GetField(behavior.InjectableField),
                                                                                    behavior.IsPasswordField));
        }

        public void AddAntiCsrfTAttributeToConfiguration(CsrfProtectionData csrfData)
        {
            AntiCsrfAttributes.TryGetValue(csrfData.HttpMethodsNameSpace, out var list);
            if (list == null)
            {
                list                                              = new List<string>();
                AntiCsrfAttributes[csrfData.HttpMethodsNameSpace] = list;
            }

            list.Add(csrfData.AntiCsrfAttribute);
        }
    }
}
