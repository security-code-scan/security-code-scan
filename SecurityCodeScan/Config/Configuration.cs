using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Config
{
    /// <summary>
    /// Internal configuration optimized for queries
    /// </summary>
    internal class Configuration
    {
        public Configuration()
        {
            _PasswordValidatorRequiredProperties = new HashSet<string>();
            PasswordValidatorRequiredProperties = new ReadOnlyHashSet<string>(_PasswordValidatorRequiredProperties);

            ConfigurationBehavior               = new Dictionary<string, KeyValuePair<string, MethodBehavior>>();
            Behavior                            = new Dictionary<string, MethodBehavior>();

            _TaintEntryPoints = new HashSet<string>();
            TaintEntryPoints  = new ReadOnlyHashSet<string>(_TaintEntryPoints);

            _AntiCsrfAttributes = new Dictionary<string, List<string>>();

            _PasswordFields = new HashSet<string>();
            PasswordFields  = new ReadOnlyHashSet<string>(_PasswordFields);

            _ConstantFields = new HashSet<string>();
            ConstantFields  = new ReadOnlyHashSet<string>(_ConstantFields);

            TaintTypeNameToBit = new Dictionary<string, ulong>(62);
        }

        public Configuration(Configuration config)
        {
            AuditMode                          = config.AuditMode;
            PasswordValidatorRequiredLength    = config.PasswordValidatorRequiredLength;
            MinimumPasswordValidatorProperties = config.MinimumPasswordValidatorProperties;

            _PasswordValidatorRequiredProperties = new HashSet<string>(config.PasswordValidatorRequiredProperties);
            PasswordValidatorRequiredProperties  = new ReadOnlyHashSet<string>(_PasswordValidatorRequiredProperties);

            ConfigurationBehavior = new Dictionary<string, KeyValuePair<string, MethodBehavior>>(config.ConfigurationBehavior);
            Behavior              = config.Behavior.ToDictionary();

            _TaintEntryPoints = new HashSet<string>(config.TaintEntryPoints);
            TaintEntryPoints  = new ReadOnlyHashSet<string>(_TaintEntryPoints);

            _AntiCsrfAttributes = config.AntiCsrfAttributes.ToDictionary();

            _PasswordFields = new HashSet<string>(config.PasswordFields);
            PasswordFields  = new ReadOnlyHashSet<string>(_PasswordFields);

            _ConstantFields = new HashSet<string>(config.ConstantFields);
            ConstantFields  = new ReadOnlyHashSet<string>(_ConstantFields);

            TaintTypeNameToBit = new Dictionary<string, ulong>(config.TaintTypeNameToBit);
        }

        public Configuration(ConfigData configData) : this()
        {
            if (configData.TaintTypes != null)
                RegisterTaintTypes(configData.TaintTypes);

            AuditMode                          = configData.AuditMode                          ?? false;
            MinimumPasswordValidatorProperties = configData.MinimumPasswordValidatorProperties ?? 0;
            PasswordValidatorRequiredLength    = configData.PasswordValidatorRequiredLength    ?? 0;

            if (configData.PasswordValidatorRequiredProperties != null)
            {
                foreach (var data in configData.PasswordValidatorRequiredProperties)
                {
                    _PasswordValidatorRequiredProperties.Add(data);
                }
            }

            foreach (var data in configData.Behavior)
            {
                ConfigurationBehavior[data.Key] = CreateBehavior(data.Value);
            }

            foreach (var source in configData.TaintEntryPoints)
            {
                if (source.Value?.Method?.ArgTypes != null)
                    throw new Exception("Taint entry point ArgTypes are not supported.");

                _TaintEntryPoints.Add(MethodBehaviorHelper.GetMethodBehaviorKey(source.Value.Namespace,
                                                                                source.Value.ClassName,
                                                                                source.Value.Name,
                                                                                source.Value?.Method?.ArgTypes));
            }

            foreach (var data in configData.CsrfProtectionAttributes)
            {
                AddAntiCsrfTAttributeToConfiguration(data);
            }

            if (configData.PasswordFields != null)
            {
                foreach (var data in configData.PasswordFields)
                {
                    _PasswordFields.Add(data.ToUpperInvariant());
                }
            }

            foreach (var data in configData.ConstantFields)
            {
                _ConstantFields.Add(data);
            }
        }

        public bool AuditMode                          { get; private set; }
        public int  PasswordValidatorRequiredLength    { get; private set; }
        public int  MinimumPasswordValidatorProperties { get; private set; }

        private readonly HashSet<string>         _PasswordValidatorRequiredProperties;
        public           ReadOnlyHashSet<string> PasswordValidatorRequiredProperties { get; }

        private readonly HashSet<string>         _TaintEntryPoints;
        public           ReadOnlyHashSet<string> TaintEntryPoints { get; }

        private readonly Dictionary<string, List<string>>          _AntiCsrfAttributes;
        public           IReadOnlyDictionary<string, List<string>> AntiCsrfAttributes => _AntiCsrfAttributes;

        private readonly HashSet<string>         _PasswordFields;
        public           ReadOnlyHashSet<string> PasswordFields { get; }

        private readonly HashSet<string>         _ConstantFields;
        public           ReadOnlyHashSet<string> ConstantFields { get; }

        private Dictionary<string, ulong> TaintTypeNameToBit { get; }

        // is needed to have allow merging by configuration Id
        private readonly Dictionary<string, KeyValuePair<string, MethodBehavior>> ConfigurationBehavior;
        // once merged the configuration Id is not used: the key is method signature parts
        public IReadOnlyDictionary<string, MethodBehavior> Behavior { get; private set; }

        public void MergeWith(ConfigData config)
        {
            if (config.TaintTypes != null)
                RegisterTaintTypes(config.TaintTypes);

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
                    _PasswordValidatorRequiredProperties.Add(property);
                }
            }

            if (config.Behavior != null)
            {
                foreach (var behavior in config.Behavior)
                {
                    if (behavior.Value == default(MethodBehaviorData))
                        ConfigurationBehavior.Remove(behavior.Key);
                    else
                        ConfigurationBehavior[behavior.Key] = CreateBehavior(behavior.Value);
                }
            }

            if (config.TaintEntryPoints != null)
            {
                foreach (var source in config.TaintEntryPoints)
                {
                    if (source.Value == default(TaintEntryPointData))
                    {
                        _TaintEntryPoints.Remove(source.Key);
                    }
                    else
                    {
                        if (source.Value?.Method?.ArgTypes != null)
                            throw new Exception("Taint entry point ArgTypes are not supported.");

                        _TaintEntryPoints.Add(MethodBehaviorHelper.GetMethodBehaviorKey(source.Value.Namespace,
                                                                                        source.Value.ClassName,
                                                                                        source.Value.Name,
                                                                                        source.Value?.Method?.ArgTypes));
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
                    _PasswordFields.Add(field.ToUpperInvariant());
                }
            }

            if (config.ConstantFields != null)
            {
                foreach (var field in config.ConstantFields)
                {
                    _ConstantFields.Add(field);
                }
            }
        }

        public void PrepareForQueries()
        {
            // Build the Behavior optimized for queries after the merge.
            Behavior = ConfigurationBehavior.Values.ToDictionary(pair => pair.Key, pair => pair.Value);
        }

        private void RegisterTaintTypes(List<string> typeNames)
        {
            var availableBit = 1ul << 3;
            foreach (var registeredBit in TaintTypeNameToBit.Values)
            {
                if (availableBit <= registeredBit)
                    availableBit = registeredBit;
            }

            foreach (var typeName in typeNames)
            {
                if (typeName == "Tainted" || typeName == "Safe" || typeName == "Constant")
                    throw new Exception("'Tainted', 'Safe', and 'Constant' are reserved taint types and cannot be used for custom taint");

                if (typeName.StartsWith("~"))
                    throw new Exception("Custom taint type cannot start from '~'");

                if (TaintTypeNameToBit.ContainsKey(typeName))
                    throw new Exception("Duplicate taint type");

                if (availableBit == 0ul)
                    throw new Exception("Max number of taint types reached");

                TaintTypeNameToBit[typeName] = availableBit;
                availableBit                  = availableBit << 1;
            }
        }

        private IReadOnlyList<Condition> GetPreConditions(Dictionary<object, object> ifSection,
                                                          IReadOnlyDictionary<int, PostCondition> mainPostConditions)
        {
            if (ifSection == null)
                return null;

            if (!ifSection.TryGetValue("Condition", out object value))
                return null;

            var configConditions = (Dictionary<object, object>)value;

            if (!ifSection.TryGetValue("Then", out value))
                return null;

            var then = (Dictionary<object, object>)value;

            var conditions = new Dictionary<int, object>(configConditions.Count);
            foreach (var argument in configConditions)
            {
                if (!(argument.Value is Dictionary<object, object> d))
                    throw new Exception("Invalid precondition format");

                var idx = int.Parse((string)argument.Key);
                if (d.Count != 1)
                    throw new Exception("Only one precondition per argument is supported");

                var condition = d.First();
                if ((string)condition.Key != "Value")
                    throw new Exception("Only 'Value' preconditions are supported");

                var conditionValue = (string)condition.Value;
                if (int.TryParse(conditionValue, out var intVal))
                    conditions.Add(idx, intVal);
                else
                    conditions.Add(idx, conditionValue);
            }

            return new List<Condition> { new Condition(conditions, GetPostConditions(then, mainPostConditions)) };
        }

        private ulong GetTaintBits(IEnumerable<object> taintTypes)
        {
            ulong bits = 0ul;
            foreach (var type in taintTypes)
            {
                var taintType = (string)type;
                bits |= GetTaintBits(taintType, out var negate);
                if (negate)
                    throw new Exception("Negation in arrays is not supported");
            }

            if (bits == 0ul)
                throw new Exception("Unknown taint type");

            return bits;
        }

        private ulong GetTaintBits(string taintType, out bool negate)
        {
            negate = false;
            if (taintType.StartsWith("~"))
            {
                negate = true;
                taintType = taintType.Substring(1);
            }

            ulong taintBits;
            switch (taintType)
            {
                case "Tainted":
                    taintBits = (ulong)VariableTaint.Tainted;
                    break;
                case "Safe":
                    taintBits = (ulong)VariableTaint.Safe;
                    break;
                case "Constant":
                    taintBits = (ulong)VariableTaint.Constant;
                    break;
                default:
                    taintBits = TaintTypeNameToBit[taintType];
                    break;
            }

            return taintBits;
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
                            case string taintType:
                            {
                                var i = int.Parse((string)indexToTaintType.Key);
                                if (i < 0)
                                    throw new Exception("Argument index cannot be negative");

                                var taintBit = TaintTypeNameToBit[taintType]; // "Tainted" is not supported
                                outArguments.Add(i, taintBit);
                                break;
                            }
                            case List<object> taintTypes:
                            {
                                ulong bits = GetTaintBits(taintTypes);
                                outArguments.Add(int.Parse((string)indexToTaintType.Key), bits);
                                break;
                            }
                            default:
                                throw new Exception("Unknown taint type");
                        }

                        break;
                    }
                    default:
                        throw new Exception("Unknown behavior argument");
                }
            }

            return outArguments;
        }

        private IReadOnlyDictionary<int, InjectableArgument> GetInjectableArguments(IReadOnlyList<object> arguments)
        {
            if (arguments == null || !arguments.Any())
                return null;

            var outArguments = new Dictionary<int, InjectableArgument>(arguments.Count);
            foreach (var argument in arguments)
            {
                switch (argument)
                {
                    case Dictionary<object, object> d when d.Count == 1:
                        {
                            var rule = d.First();
                            var ruleId = (string)rule.Key;
                            switch (rule.Value)
                            {
                                case string idxText:
                                {
                                    int idx = int.Parse(idxText);
                                    if (idx < 0)
                                        throw new Exception("Argument index cannot be negative");

                                    outArguments.Add(idx, new InjectableArgument((ulong)VariableTaint.Safe, ruleId));
                                    break;
                                }
                                case List<object> indices:
                                    foreach (var index in indices)
                                    {
                                        switch (index)
                                        {
                                            case string idxText:
                                            {
                                                int idx = int.Parse(idxText);
                                                if (idx < 0)
                                                    throw new Exception("Argument index cannot be negative");

                                                outArguments.Add(idx, new InjectableArgument((ulong)VariableTaint.Safe, ruleId));
                                                break;
                                            }
                                            case Dictionary<object, object> idxToTaints when idxToTaints.Count == 1:
                                            {
                                                var idxToTaint = idxToTaints.First();
                                                var idxText = (string)idxToTaint.Key;
                                                int idx = int.Parse(idxText);
                                                if (idx < 0)
                                                    throw new Exception("Argument index cannot be negative");

                                                var taintBit = GetTaintBits((string)idxToTaint.Value, out var negate);
                                                outArguments.Add(idx, new InjectableArgument(taintBit, ruleId, negate));
                                                break;
                                            }
                                            default:
                                                throw new Exception("Unknown behavior argument");
                                        }
                                    }
                                    break;
                                default:
                                    throw new Exception("Unknown behavior argument");
                            }
                            break;
                        }
                    default:
                        throw new Exception("Unknown behavior argument");
                }
            }

            return outArguments;
        }

        private IReadOnlyDictionary<int, PostCondition> GetPostConditions(IReadOnlyDictionary<object, object> arguments,
                                                                          IReadOnlyDictionary<int, PostCondition> defaultPostConditions = null)
        {
            if (arguments == null || !arguments.Any())
                return null;

            var conditions = new Dictionary<int, PostCondition>(arguments.Count);
            foreach (var argument in arguments)
            {
                var argKey = (string)argument.Key;
                if (argKey == "ArgTypes" || argKey == "If" || argKey == "InjectableArguments")
                    continue;

                if (!(argument.Value is Dictionary<object, object> d))
                    throw new Exception("Invalid postcondition format");

                var                   idx                = argKey == "Returns" ? -1 : int.Parse(argKey);
                ulong                 taintBit           = 0ul;
                ImmutableHashSet<int> taintFromArguments = null;

                foreach (var condition in d)
                {
                    var conditionKey = (string)condition.Key;
                    switch (conditionKey)
                    {
                        case "Taint":
                            switch (condition.Value)
                            {
                                case string taintType:
                                    taintBit = GetTaintBits(taintType, out var negate);
                                    if (negate)
                                        throw new Exception("Negation in postconditions is not supported");
                                break;
                                case List<object> taintTypes:
                                    taintBit = GetTaintBits(taintTypes);
                                    break;
                            }

                            break;
                        case "TaintFromArguments":
                            var taintFrom = (List<object>)condition.Value;
                            if (taintFrom != null && taintFrom.Count == 0)
                            {
                                throw new Exception("Do not specify 'TaintFromArguments' or provide at least one value");
                            }

                            var args = GetArguments(taintFrom);
                            if (args.Values.Any(x => x != (ulong)VariableTaint.Safe))
                                throw new Exception("'TaintFromArguments' supports only array of indices");

                            taintFromArguments = args.Keys.ToImmutableHashSet();
                            break;
                        default:
                            throw new Exception("Only 'Taint' and 'TaintFromArguments' are supported in postconditions");
                    }
                }

                if (defaultPostConditions != null)
                {
                    if (taintBit == 0ul)
                        taintBit = defaultPostConditions[idx].Taint;

                    if (taintFromArguments == null)
                        taintFromArguments = defaultPostConditions[idx].TaintFromArguments;
                }

                conditions.Add(idx, new PostCondition(taintBit, taintFromArguments));
            }

            return conditions;
        }

        private InjectableArgument GetField(object value)
        {
            if (value == null)
                return null;

            switch (value)
            {
                case string s:
                    return new InjectableArgument((ulong)VariableTaint.Safe, s);
                case List<object> taintTypes when taintTypes.Count == 1:
                {
                    var types = (Dictionary<object, object>)taintTypes.First();
                    if (types.Count != 1)
                        throw new Exception("Unknown injectable argument");

                    var t = types.First();
                    var taintBits = GetTaintBits((string)t.Value, out var negate);
                    return new InjectableArgument(taintBits, (string)t.Key, negate);
                }
                default:
                    throw new Exception("Unknown injectable argument");
            }
        }

        private readonly char[] Parenthesis = { '(', ')' };

        private void ValidateArgTypes(string argTypes, string nameSpace, string className, string name)
        {
            if (argTypes == null)
                return;

            if (argTypes.Length == 0)
                throw new Exception($"Do not specify 'ArgTypes:' in {nameSpace}.{className}.{name} to match any overload");

            if (argTypes.Trim() != argTypes)
                throw new Exception($"Leading or trailing white space in {nameSpace}.{className}.{name}");

            if (argTypes[0] != '(' || argTypes[argTypes.Length - 1] != ')')
                throw new Exception($"Invalid parenthesis in {nameSpace}.{className}.{name}");

            argTypes = argTypes.Substring(1, argTypes.Length - 2);
            if (argTypes.IndexOfAny(Parenthesis) != -1)
                throw new Exception($"Parenthesis detected inside of 'ArgTypes:' in {nameSpace}.{className}.{name}");

            if (argTypes != string.Empty)
            {
                foreach (var argType in argTypes.Split(new[] { ", " }, StringSplitOptions.None))
                {
                    if (argType.Trim() != argType)
                        throw new Exception(
                            $"Leading or trailing white space in argument of {nameSpace}.{className}.{name}");

                    if (!argType.Contains("."))
                        throw new Exception($"Argument type lacks namespace in {nameSpace}.{className}.{name}");

                    if (argType.Contains("this "))
                        throw new Exception($"'this' keyword should be omitted in {nameSpace}.{className}.{name}");

                    var arg = argType;
                    if (argType.Contains("params "))
                        arg = argType.Replace("params ", "");
                    if (argType.Contains("out "))
                        arg = argType.Replace("out ", "");

                    if (arg.Contains(" "))
                        throw new Exception($"Argument name should be omitted in {nameSpace}.{className}.{name}");
                }
            }
        }

        private KeyValuePair<string, MethodBehavior> CreateBehavior(object behavior)
        {
            var behaviorDict = (Dictionary<object, object>)behavior;

            string nameSpace = null;
            if (behaviorDict.TryGetValue("Namespace", out object value))
                nameSpace = (string)value;

            string className = null;
            if (behaviorDict.TryGetValue("ClassName", out value))
                className = (string)value;

            string name = null;
            if (behaviorDict.TryGetValue("Name", out value))
                name = (string)value;

            string                     argTypes            = null;
            Dictionary<object, object> ifCondition         = null;
            IReadOnlyList<object>      injectableArguments = null;

            Dictionary<object, object> method = null;
            if (behaviorDict.TryGetValue("Method", out value))
            {
                method = (Dictionary<object, object>)value;
                if (method.TryGetValue("ArgTypes", out value))
                {
                    argTypes = (string)value;
                    ValidateArgTypes(argTypes, nameSpace, className, name);
                }

                if (method.TryGetValue("If", out value))
                    ifCondition = (Dictionary<object, object>)value;

                if (method.TryGetValue("InjectableArguments", out value))
                    injectableArguments = (IReadOnlyList<object>)value;
            }

            object injectable = null;

            if (behaviorDict.TryGetValue("Field", out value))
            {
                var field = (Dictionary<object, object>)value;

                if (field.TryGetValue("Injectable", out value))
                    injectable = value;
            }

            var key = MethodBehaviorHelper.GetMethodBehaviorKey(nameSpace, className, name, argTypes);

            var mainPostConditions = GetPostConditions(method);
            return new KeyValuePair<string, MethodBehavior>(key, new MethodBehavior(GetPreConditions(ifCondition, mainPostConditions),
                                                                                    mainPostConditions,
                                                                                    GetInjectableArguments(injectableArguments),
                                                                                    GetField(injectable)));
        }

        public void AddAntiCsrfTAttributeToConfiguration(CsrfProtectionData csrfData)
        {
            AntiCsrfAttributes.TryGetValue(csrfData.HttpMethodsNameSpace, out var list);
            if (list == null)
            {
                list                                               = new List<string>();
                _AntiCsrfAttributes[csrfData.HttpMethodsNameSpace] = list;
            }

            list.Add(csrfData.AntiCsrfAttribute);
        }
    }
}
