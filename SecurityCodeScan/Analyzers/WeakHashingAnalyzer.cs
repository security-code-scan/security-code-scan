using System.Collections.Generic;
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
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class WeakHashingAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor Md5Rule  = LocaleUtil.GetDescriptor("SCS0006", new[] { "MD5" });
        private static readonly DiagnosticDescriptor Sha1Rule = LocaleUtil.GetDescriptor("SCS0006", new[] { "SHA1" });

        private static readonly ImmutableDictionary<string, DiagnosticDescriptor> HashFunctions = new Dictionary<string, DiagnosticDescriptor>
        {
            { "MD5", Md5Rule },
            { "SHA1", Sha1Rule }
        }.ToImmutableDictionary();

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Md5Rule,
                                                                                                           Sha1Rule);

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

            foreach (KeyValuePair<string, DiagnosticDescriptor> entry in HashFunctions)
            {
                //XXX.Create()
                if (!AnalyzerUtil.SymbolMatch(symbol, type: entry.Key, name: "Create"))
                    continue;

                var diagnostic = Diagnostic.Create(entry.Value, expression.GetLocation(), "MD5");
                ctx.ReportDiagnostic(diagnostic);
            }
        }
    }
}
