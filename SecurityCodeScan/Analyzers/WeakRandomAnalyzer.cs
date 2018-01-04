using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class WeakRandomAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0005");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, CSharp.SyntaxKind.InvocationExpression);
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, VB.SyntaxKind.InvocationExpression);
        }

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            SyntaxNode node;
            SyntaxNode expression;

            if (ctx.Node.Language == LanguageNames.CSharp)
            {
                node       = ctx.Node as CSharpSyntax.InvocationExpressionSyntax;
                expression = ((CSharpSyntax.InvocationExpressionSyntax)node)?.Expression;
            }
            else
            {
                node       = ctx.Node as VBSyntax.InvocationExpressionSyntax;
                expression = ((VBSyntax.InvocationExpressionSyntax)node)?.Expression;
            }

            if (node == null)
                return;

            var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;

            //System.Random.Next()
            if (AnalyzerUtil.SymbolMatch(symbol, type: "Random", name: "Next")      ||
                AnalyzerUtil.SymbolMatch(symbol, type: "Random", name: "NextBytes") ||
                AnalyzerUtil.SymbolMatch(symbol, type: "Random", name: "NextDouble"))
            {
                var diagnostic = Diagnostic.Create(Rule, expression.GetLocation());
                ctx.ReportDiagnostic(diagnostic);
            }
        }
    }
}
