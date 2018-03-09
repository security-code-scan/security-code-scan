using System;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;

namespace SecurityCodeScan.Analyzers.Utils
{
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
                                    typeQualificationStyle: SymbolDisplayTypeQualificationStyle.NameAndContainingTypesAndNamespaces);

        public static bool IsType(this ISymbol symbol, string type)
        {
            return symbol.ToDisplayString(SymbolDisplayFormat) == type;
        }

        public static string GetTypeName(this ISymbol symbol)
        {
            return symbol.ToDisplayString(SymbolDisplayFormat);
        }

        public static bool IsTypeOrDerivedFrom(this ITypeSymbol symbol, params string[] types)
        {
            foreach (var type in types)
            {
                if (symbol.IsType(type))
                    return true;
            }
            return symbol.IsDerivedFrom(types);
        }

        public static bool IsDerivedFrom(this ITypeSymbol symbol, params string[] types)
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

        public static bool HasDerivedClassAttribute(this ITypeSymbol symbol, Func<AttributeData, bool> condition)
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

        public static bool HasDerivedMethodAttribute(this IMethodSymbol symbol, Func<AttributeData, bool> condition)
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

    internal class AnalyzerUtil
    {
        public static bool SymbolMatch(ISymbol symbol, string type = null, string name = null)
        {
            if (symbol == null)
            {
                //Code did not compile
                //FIXME: Log warning
                return false;
            }

            if (type == null && name == null)
            {
                throw new InvalidOperationException("At least one parameter must be specified (type, methodName, ...)");
            }

            if (type != null && symbol.ContainingType?.Name != type)
            {
                return false; //Class name does not match
            }

            if (name != null && symbol.Name != name)
            {
                return false; //Method name does not match
            }

            return true;
        }
    }
}
