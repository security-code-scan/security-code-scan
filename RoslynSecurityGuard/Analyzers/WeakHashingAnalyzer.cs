using Microsoft.CodeAnalysis;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

using System.Collections.Generic;
using System.Collections.Immutable;

using RoslynSecurityGuard.Analyzers.Utils;
using RoslynSecurityGuard.Analyzers.Locale;


namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
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
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, CSharp.SyntaxKind.InvocationExpression);
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, VB.SyntaxKind.InvocationExpression);
        }

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            SyntaxNode node, expression;
            if (ctx.Node.Language == LanguageNames.CSharp)
            {
                node = ctx.Node as CSharpSyntax.InvocationExpressionSyntax;
                expression = ((CSharpSyntax.InvocationExpressionSyntax)node)?.Expression;
            } else
            {
                node = ctx.Node as VBSyntax.InvocationExpressionSyntax;
                expression = ((VBSyntax.InvocationExpressionSyntax)node)?.Expression;
            }
            
            if (node == null) return;

            var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;

            foreach (KeyValuePair<string, DiagnosticDescriptor> entry in HashFunctions) {
                //XXX.Create()
                if (AnalyzerUtil.SymbolMatch(symbol, type: entry.Key, name: "Create"))
                {
                    var diagnostic = Diagnostic.Create(entry.Value, expression.GetLocation(), "MD5");
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
        }
    }
}