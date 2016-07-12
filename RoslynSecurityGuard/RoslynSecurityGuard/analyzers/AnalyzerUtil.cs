using Microsoft.CodeAnalysis;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Microsoft.CodeAnalysis.Internal.Log;
using Microsoft.CodeAnalysis.CSharp;

namespace RoslynSecurityGuard.Analyzers
{
    public class AnalyzerUtil
    {
        
        

        public static DiagnosticDescriptor GetDescriptorFromResource(Type analyzer, DiagnosticSeverity severity) {
            return new DiagnosticDescriptor(GetLocalString(analyzer.Name + "_Id").ToString(),
                GetLocalString(analyzer.Name + "_Title"),
                GetLocalString(analyzer.Name + "_Message"),
                "Security", 
                severity, 
                isEnabledByDefault: true,
                helpLinkUri : "https://github.com/fxcop-security-guard/#"+GetLocalString(analyzer.Name + "_Id").ToString(),
                description : GetLocalString(analyzer.Name + "_Title"));
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

        public static Boolean IsStaticString(ExpressionSyntax expression) {
            if (expression.Kind() == SyntaxKind.StringLiteralExpression && expression is LiteralExpressionSyntax) {
                return true;
            }
            else {
                return false; //FIXME: Improved the analysis
            }
        }
    }
}
