//using Microsoft.CodeAnalysis;
//using Microsoft.CodeAnalysis.CSharp;
//using Microsoft.CodeAnalysis.CSharp.Syntax;
//using Microsoft.CodeAnalysis.Diagnostics;
//using System.Collections.Immutable;
//using System.Text.RegularExpressions;
//using RoslynSecurityGuard.Analyzers.Utils;
//using RoslynSecurityGuard.Analyzers.Locale;

//namespace RoslynSecurityGuard.Analyzers
//{
//    [DiagnosticAnalyzer(LanguageNames.CSharp)]
//    public class LinqSqlInjectionAnalyzer : DiagnosticAnalyzer
//    {
//        private static DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SG0002");

//        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

//        public override void Initialize(AnalysisContext context)
//        {
//            context.RegisterSyntaxNodeAction(VisitSyntaxNode, SyntaxKind.InvocationExpression);
//        }

//        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
//        {
            
//            InvocationExpressionSyntax node = ctx.Node as InvocationExpressionSyntax;
//            if (node != null) {
//                var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;

//                //DataContext.ExecuteQuery()
//                if (AnalyzerUtil.SymbolMatch(symbol, type: "DataContext", name: "ExecuteQuery")) {

//                    var sig = symbol.ToDisplayString(); //Signature with the full class name and argument types
//                    var args = node.ArgumentList.Arguments;

//                    //Actual string in the test sample "System.Data.Linq.DataContext.ExecuteQuery<VulnerableApp.UserEntity>(string, params object[])"
//                    var sigExecQueryGeneric = new Regex(@"System\.Data\.Linq\.DataContext\.ExecuteQuery<[\w\.]+>\(string, params object\[\]\)");
//                    var sigExecQueryType = "System.Data.Linq.DataContext.ExecuteQuery(System.Type, string, params object[])";

//                    if ((sigExecQueryGeneric.IsMatch(sig) && !AnalyzerUtil.IsStaticString(args[0].Expression)) ||
//                        (sigExecQueryType == sig && !AnalyzerUtil.IsStaticString(args[1].Expression)))
//                    {
//                        var diagnostic = Diagnostic.Create(Rule, node.Expression.GetLocation());
//                        ctx.ReportDiagnostic(diagnostic);
//                    }
//                }
//            }

//        }
        
//    }
//}
