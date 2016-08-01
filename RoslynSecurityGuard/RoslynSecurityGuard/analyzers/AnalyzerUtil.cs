using Microsoft.CodeAnalysis;
using System;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Text;

namespace RoslynSecurityGuard.Analyzers
{
    public class AnalyzerUtil
    {

        public static DiagnosticDescriptor GetDescriptorFromResource(string id,string localeId, DiagnosticSeverity severity) {
            return new DiagnosticDescriptor(id,
                GetLocalString(localeId + "_Title"),
                GetLocalString(localeId + "_Title"),
                "Security", 
                severity, 
                isEnabledByDefault: true,
                helpLinkUri : "https://dotnet-security-guard.github.io/rules.htm#" + localeId,
                description : GetLocalString(localeId + "_Message"));
        }

        private static LocalizableString GetLocalString(string id) {
            return new LocalizableResourceString(id, Messages.ResourceManager, typeof(Messages));
        }

        public static bool InvokeMatch(ISymbol symbol, string className = null, string method = null) {
            if (symbol == null) { //Code did not compile
                //FIXME: Log warning
                return false;
            }

            if (className == null && method == null) {
                throw new InvalidOperationException("At least one parameter must be specified (className, methodName, ...)");
            }

            if (className != null && symbol.ContainingType?.Name != className) {
                return false; //Class name does not match
            }
            if (method != null && symbol.Name != method) {
                return false; //Method name does not match
            }
            return true;
        }

        internal static bool ValueIsExternal(DataFlowAnalysis flow, ArgumentSyntax arg) {
            
            return true;
        }

        public static SyntaxNode GetMethodFromNode(SyntaxNode node) {

            SyntaxNode current = node;
            while (current.Parent != null) {
                current = current.Parent;
            }
            return current;
        }

        public static bool IsStaticString(ExpressionSyntax expression)
        {
            //FIXME: Improved the analysis
            //Temporary implementation..
            return expression.Kind() == SyntaxKind.StringLiteralExpression && expression is LiteralExpressionSyntax;
        }


        public static Location CreateLocation(string path, int lineStart, int linePosition = -1)
        {
            return Location.Create(path, TextSpan.FromBounds(1, 2), new LinePositionSpan(new LinePosition(lineStart, 0), new LinePosition(lineStart, 0)));
        }
    }
}
