using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System.Collections.Immutable;
using RoslynSecurityGuard.Analyzers.Utils;
using RoslynSecurityGuard.Analyzers.Locale;
using System.Collections.Generic;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class WeakHashingAnalyzer : DiagnosticAnalyzer
    {
        private static DiagnosticDescriptor Md5Rule = LocaleUtil.GetDescriptor("SG0006",new string[] { "MD5" });
        private static DiagnosticDescriptor Sha1Rule = LocaleUtil.GetDescriptor("SG0006", new string[] { "SHA1" });

        private static readonly ImmutableDictionary<string, DiagnosticDescriptor> HashFunctions = new Dictionary<string, DiagnosticDescriptor> {
            { "MD5", Md5Rule }, { "SHA1", Sha1Rule }
        }.ToImmutableDictionary();

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Md5Rule, Sha1Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, SyntaxKind.InvocationExpression);
        }

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {

            var node = ctx.Node as InvocationExpressionSyntax;
            if (node == null) return;

            var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;

            foreach (KeyValuePair<string, DiagnosticDescriptor> entry in HashFunctions) {
                //XXX.Create()
                if (AnalyzerUtil.SymbolMatch(symbol, type: entry.Key, name: "Create"))
                {
                    var diagnostic = Diagnostic.Create(entry.Value, node.Expression.GetLocation(), "MD5");
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
        }
    }
}