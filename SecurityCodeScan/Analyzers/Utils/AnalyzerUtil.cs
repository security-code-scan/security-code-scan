using System;
using System.Collections.Generic;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

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
        public static readonly SymbolDisplayFormat SymbolDisplayFormat =
            new SymbolDisplayFormat(memberOptions: SymbolDisplayMemberOptions.IncludeContainingType, typeQualificationStyle: SymbolDisplayTypeQualificationStyle.NameAndContainingTypesAndNamespaces);

        public static bool IsType(this ISymbol symbol, string type)
        {
            return symbol.ToDisplayString(SymbolDisplayFormat) == type;
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

        private static bool HasAttribute(this ISymbol symbol, Func<AttributeData, bool> condition)
        {
            var attributes = symbol.GetAttributes();
            foreach (var attributeData in attributes)
            {
                if (condition(attributeData))
                    return true;
            }

            return false;
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

        public static void ForEachAnnotation(SyntaxList<CSharpSyntax.AttributeListSyntax> attributes,
                                             Action<string, CSharpSyntax.AttributeSyntax> callback)
        {
            foreach (var attribute in attributes)
            {
                if (attribute.Attributes.Count == 0)
                    continue; //Bound check .. Unlikely to happen

                //Extract the annotation identifier
                if (!(attribute.Attributes[0].Name is CSharpSyntax.IdentifierNameSyntax identifier))
                    continue;

                callback(identifier.Identifier.Text, attribute.Attributes[0]);
            }
        }

        public static SyntaxNode GetMethodFromNode(SyntaxNode node)
        {
            SyntaxNode current = node;
            while (current.Parent != null)
            {
                current = current.Parent;
            }

            return current;
        }

        public static List<string> GetAttributesForMethod(CSharpSyntax.MethodDeclarationSyntax node)
        {
            var attributesList = new List<string>();

            foreach (CSharpSyntax.AttributeListSyntax attributeList in node.AttributeLists)
            {
                foreach (CSharpSyntax.AttributeSyntax attribute in attributeList.Attributes)
                    attributesList.Add(attribute.Name.GetText().ToString());
            }

            return attributesList;
        }

        public static List<string> GetAttributesForMethod(VBSyntax.MethodBlockSyntax node)
        {
            var attributesList = new List<string>();

            foreach (VBSyntax.AttributeListSyntax attributeList in node.SubOrFunctionStatement.AttributeLists)
            {
                foreach (VBSyntax.AttributeSyntax attribute in attributeList.Attributes)
                    attributesList.Add(attribute.Name.GetText().ToString());
            }

            return attributesList;
        }

        public static List<CSharpSyntax.AttributeSyntax> GetAttributesByName(string attributeName,
                                                                             CSharpSyntax.MethodDeclarationSyntax node)
        {
            var attributesList = new List<CSharpSyntax.AttributeSyntax>();

            if (node?.AttributeLists == null)
                return attributesList;

            foreach (CSharpSyntax.AttributeListSyntax attributeList in node.AttributeLists)
            {
                foreach (CSharpSyntax.AttributeSyntax attribute in attributeList.Attributes)
                {
                    if (attribute.Name.GetText().ToString().Equals(attributeName))
                    {
                        attributesList.Add(attribute);
                    }
                }
            }

            return attributesList;
        }

        public static List<VBSyntax.AttributeSyntax> GetAttributesByName(string attributeName,
                                                                         VBSyntax.MethodBlockSyntax node)
        {
            var attributesList = new List<VBSyntax.AttributeSyntax>();

            if (node?.SubOrFunctionStatement?.AttributeLists == null)
                return attributesList;

            foreach (VBSyntax.AttributeListSyntax attributeList in node.SubOrFunctionStatement.AttributeLists)
            {
                foreach (VBSyntax.AttributeSyntax attribute in attributeList.Attributes)
                {
                    if (attribute.Name.GetText().ToString().Equals(attributeName))
                    {
                        attributesList.Add(attribute);
                    }
                }
            }

            return attributesList;
        }

        /// <summary>
        /// Verify is the expression passed is a constant string.
        /// </summary>
        /// <param name="expression"></param>
        /// <returns></returns>
        [Obsolete]
        public static bool IsStaticString(CSharpSyntax.ExpressionSyntax expression)
        {
            return expression.Kind() == CSharp.SyntaxKind.StringLiteralExpression &&
                   expression is CSharpSyntax.LiteralExpressionSyntax;
        }
    }
}
