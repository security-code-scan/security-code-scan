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
    public class WeakCipherAnalyzerCSharp : WeakCipherAnalyzer
    {
        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(ctx => VisitSyntaxNode(ctx, CSharpSyntaxNodeHelper.Default),
                                             CSharp.SyntaxKind.InvocationExpression,
                                             CSharp.SyntaxKind.ObjectCreationExpression);
        }
    }

    [DiagnosticAnalyzer(LanguageNames.VisualBasic)]
    public class WeakCipherAnalyzerVisualBasic : WeakCipherAnalyzer
    {
        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(ctx => VisitSyntaxNode(ctx, VBSyntaxNodeHelper.Default),
                                             VB.SyntaxKind.InvocationExpression,
                                             VB.SyntaxKind.ObjectCreationExpression);
        }
    }

    public abstract class WeakCipherAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0010");

        private static readonly ImmutableArray<string> BadCiphers = ImmutableArray.Create("DES", "RC2");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        protected static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
        {
            var expression = nodeHelper.GetInvocationExpressionNode(ctx.Node);
            if (expression != null)
            {
                var symbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;

                foreach (string cipher in BadCiphers)
                {
                    if (!AnalyzerUtil.SymbolMatch(symbol, type: cipher, name: "Create"))
                        continue;

                    var diagnostic = Diagnostic.Create(Rule, expression.GetLocation(), cipher);
                    ctx.ReportDiagnostic(diagnostic);
                }
            }

            if (nodeHelper.IsObjectCreationExpressionNode(ctx.Node))
            {
                var symbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;

                foreach (string cipher in BadCiphers)
                {
                    if (!AnalyzerUtil.SymbolMatch(symbol, type: cipher + "CryptoServiceProvider"))
                        continue;

                    var diagnostic = Diagnostic.Create(Rule, ctx.Node.GetLocation(), cipher);
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
        }
    }
}
