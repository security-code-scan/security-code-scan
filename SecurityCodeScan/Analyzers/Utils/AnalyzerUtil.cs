#nullable disable
using System;
using System.Collections;
using System.Collections.Generic;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Analyzers.Utils
{
    internal static class AnalysisContextExtensions
    {
        public static bool IsAuditMode(this AnalysisContext context)
        {
            var config = Configuration.GetOrCreate(context);
            return config.AuditMode.HasValue && config.AuditMode.Value;
        }
    }

    internal static class XElementExtensions
    {
        public static string ToStringStartElement(this XElement e)
        {
            var element = e.ToString();
            return element.Substring(0, element.IndexOf('>') + 1);
        }
    }

    internal static class SymbolExtensions
    {
        private static readonly SymbolDisplayFormat SymbolDisplayFormat =
            new SymbolDisplayFormat(memberOptions: SymbolDisplayMemberOptions.IncludeContainingType,
                                    parameterOptions: SymbolDisplayParameterOptions.IncludeType,
                                    typeQualificationStyle: SymbolDisplayTypeQualificationStyle.NameAndContainingTypesAndNamespaces);

        public static bool IsType(this ISymbol symbol, string type)
        {
            return symbol.ToDisplayString(SymbolDisplayFormat) == type;
        }

        public static string GetTypeName(this ISymbol symbol)
        {
            return symbol.ToDisplayString(SymbolDisplayFormat);
        }

        public static bool IsTypeOrDerivedFrom(this ITypeSymbol symbol, IEnumerable<string> types)
        {
            foreach (var type in types)
            {
                if (symbol.IsType(type))
                    return true;
            }
            return symbol.IsDerivedFrom(types);
        }

        public static bool IsTypeOrDerivedFrom(this ITypeSymbol symbol, IEnumerable<string> types, out string foundType)
        {
            foreach (var type in types)
            {
                if (symbol.IsType(type))
                {
                    foundType = type;
                    return true;
                }
            }

            return symbol.IsDerivedFrom(types, out foundType);
        }

        public static bool IsDerivedFrom(this ITypeSymbol symbol, string type)
        {
            while (symbol.BaseType != null)
            {
                symbol = symbol.BaseType;

                if (symbol.IsType(type))
                    return true;
            }

            return false;
        }

        public static bool IsDerivedFrom(this ITypeSymbol symbol, IEnumerable<string> types)
        {
            while (symbol.BaseType != null)
            {
                symbol = symbol.BaseType;

                foreach (var type in types)
                {
                    if (symbol.IsType(type))
                        return true;
                }
            }

            return false;
        }

        public static bool IsDerivedFrom(this ITypeSymbol symbol, IEnumerable<string> types, out string foundType)
        {
            while (symbol.BaseType != null)
            {
                symbol = symbol.BaseType;

                foreach (var type in types)
                {
                    if (symbol.IsType(type))
                    {
                        foundType = type;
                        return true;
                    }
                }
            }

            foundType = null;
            return false;
        }

        public static bool HasAttribute(this ISymbol symbol, Func<AttributeData, bool> condition)
        {
            var attributes = symbol.GetAttributes();
            foreach (var attributeData in attributes)
            {
                if (condition(attributeData))
                    return true;
            }

            return false;
        }

        public static AttributeData GetAttribute(this ISymbol symbol, Func<AttributeData, bool> condition)
        {
            var attributes = symbol.GetAttributes();
            foreach (var attributeData in attributes)
            {
                if (condition(attributeData))
                    return attributeData;
            }

            return null;
        }

        public static bool HasDerivedAttribute(this ITypeSymbol symbol, Func<AttributeData, bool> condition)
        {
            while (symbol != null)
            {
                if (symbol.HasAttribute(condition))
                    return true;

                if (symbol.BaseType == null)
                    return false;

                symbol = symbol.BaseType;
            }

            return false;
        }

        public static AttributeData TryGetDerivedAttribute(this ITypeSymbol symbol, Func<AttributeData, bool> condition)
        {
            while (symbol != null)
            {
                var attr = symbol.GetAttribute(condition);
                if (attr != null)
                    return attr;

                if (symbol.BaseType == null)
                    return null;

                symbol = symbol.BaseType;
            }

            return null;
        }

        public static bool HasDerivedAttribute(this IMethodSymbol symbol, Func<AttributeData, bool> condition)
        {
            while (symbol != null)
            {
                if (symbol.HasAttribute(condition))
                    return true;

                if (symbol.OverriddenMethod == null)
                    return false;

                symbol = symbol.OverriddenMethod;
            }

            return false;
        }

        public static AttributeData TryGetDerivedAttribute(this IMethodSymbol symbol, Func<AttributeData, bool> condition)
        {
            while (symbol != null)
            {
                var attr = symbol.GetAttribute(condition);
                if (attr != null)
                    return attr;

                if (symbol.OverriddenMethod == null)
                    return null;

                symbol = symbol.OverriddenMethod;
            }

            return null;
        }
    }

    internal static class ExternalDiagnostic
    {
        public static Diagnostic Create(DiagnosticDescriptor descriptor, string path, int line, string source)
        {
            return Diagnostic.Create(descriptor, Location.None, path, line, source);
        }
    }

    internal static class IntExtensions
    {
        public static string ToNthString(this int i)
        {
            switch (i)
            {
                case 1:
                    return $"{i}st";
                case 2:
                    return $"{i}nd";
                case 3:
                    return $"{i}rd";
                default:
                    return $"{i}th";
            }
        }
    }

    internal static class EmptyArray<T>
    {
        public static readonly T[] Value = new T[0];
    }

    internal static class EmptyList<T>
    {
        public static readonly IReadOnlyList<T> Value = new List<T>();
    }

    internal static class EmptyDictionary<TKey, TVal>
    {
        public static readonly IReadOnlyDictionary<TKey, TVal> Value = new Dictionary<TKey, TVal>();
    }

    internal static class IReadOnlyDictionaryExtensions
    {
        public static Dictionary<TKey, TValue> ToDictionary<TKey, TValue>(this IReadOnlyDictionary<TKey, TValue> readOnlyDictionary, IEqualityComparer<TKey> comparer = null)
        {
            var dictionary = new Dictionary<TKey, TValue>(readOnlyDictionary.Count, comparer);
            foreach (var keyValuePair in readOnlyDictionary)
                dictionary.Add(keyValuePair.Key, keyValuePair.Value);

            return dictionary;
        }
    }

    internal class ReadOnlyHashSet<T> : IReadOnlyCollection<T>
    {
        private readonly HashSet<T> Set;

        public ReadOnlyHashSet(HashSet<T> set)
        {
            Set = set;
        }

        public bool Contains(T item)
        {
            return Set.Contains(item);
        }

        public IEnumerator<T> GetEnumerator()
        {
            return Set.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return ((IEnumerable)Set).GetEnumerator();
        }

        public int Count => Set.Count;
    }
}
