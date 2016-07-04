using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace RoslynSecurityGuard
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class LinqSqlInjectionAnalyzer : DiagnosticAnalyzer
    {

        private static DiagnosticDescriptor Rule = AnalyzerUtil.GetDescriptorFromResource(typeof(LinqSqlInjectionAnalyzer), DiagnosticSeverity.Warning);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get { return ImmutableArray.Create(Rule); } }

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, SyntaxKind.InvocationExpression);
        }

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            
            InvocationExpressionSyntax node = ctx.Node as InvocationExpressionSyntax;
            if (node != null) {
                var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;

                //DataContext.ExecuteQuery()
                if (AnalyzerUtil.InvokeMatch(symbol, className : "DataContext", method: "ExecuteQuery")) {

                    var sig = symbol.ToDisplayString(); //Signature with the full class name and argument types
                    var args = node.ArgumentList.Arguments;

                    //Actual string in the test sample "System.Data.Linq.DataContext.ExecuteQuery<VulnerableApp.UserEntity>(string, params object[])"
                    var sigExecQueryGeneric = new Regex(@"System\.Data\.Linq\.DataContext\.ExecuteQuery<[\w\.]+>\(string, params object\[\]\)");
                    var sigExecQueryType = "System.Data.Linq.DataContext.ExecuteQuery(System.Type, string, params object[])";

                    if ((sigExecQueryGeneric.IsMatch(sig) && !AnalyzerUtil.IsStaticString(args[0].Expression)) ||
                        (sigExecQueryType == sig && !AnalyzerUtil.IsStaticString(args[1].Expression)))
                    {
                        var diagnostic = Diagnostic.Create(Rule, node.Expression.GetLocation(), new string[0]);
                        ctx.ReportDiagnostic(diagnostic);
                    }
                }
            }

        }
        
    }
}
