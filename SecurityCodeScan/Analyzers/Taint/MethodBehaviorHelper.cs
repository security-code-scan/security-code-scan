#nullable disable
using System;
using System.Collections.Generic;
using Microsoft.CodeAnalysis;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Analyzers.Taint
{
    internal static class MethodBehaviorHelper
    {
        public static string GetMethodBehaviorKey(string nameSpace, string className, string name, string argTypes)
        {
            if (string.IsNullOrWhiteSpace(className))
                throw new ArgumentException("ClassName");

            string nameSpacePrefix = string.IsNullOrWhiteSpace(nameSpace) ? "" : $"{nameSpace}.";

            string key;
            if (argTypes != null)
            {
                if (string.IsNullOrWhiteSpace(name))
                    throw new ArgumentException("Name");

                key = $"{nameSpacePrefix}{className}|{name}|{argTypes}";
            }
            else if (name != null)
            {
                key = $"{nameSpacePrefix}{className}|{name}";
            }
            else
            {
                key = $"{nameSpacePrefix}{className}";
            }

            return key;
        }

        public static bool IsTaintType(this ITypeSymbol symbol, IReadOnlyDictionary<string, MethodBehavior> behaviors)
        {
            string key = symbol.GetTypeName();
            if (!behaviors.TryGetValue(key, out var behavior))
                return false;

            if (behavior.PostConditions.TryGetValue((int)ArgumentIndex.Returns, out PostCondition postCondition))
                return postCondition.Taint == (uint)VariableTaint.Tainted;

            return false;
        }
    }
}
