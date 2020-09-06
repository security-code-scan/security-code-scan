using System.Collections.Immutable;
using System.Diagnostics;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using VB = Microsoft.CodeAnalysis.VisualBasic;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class WeakCipherAnalyzerCSharp : WeakCipherAnalyzer
    {
        public override void Initialize(AnalysisContext context)
        {
            if (!Debugger.IsAttached) // prefer single thread for debugging in development
                context.EnableConcurrentExecution();

            if (context.IsAuditMode())
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            else
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context)
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
            if (!Debugger.IsAttached) // prefer single thread for debugging in development
                context.EnableConcurrentExecution();

            if (context.IsAuditMode())
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            else
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(ctx => VisitSyntaxNode(ctx, VBSyntaxNodeHelper.Default),
                                             VB.SyntaxKind.InvocationExpression,
                                             VB.SyntaxKind.ObjectCreationExpression);
        }
    }

    public abstract class WeakCipherAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0010");

        private static readonly ImmutableArray<string> BadCipherCreate = ImmutableArray.Create("System.Security.Cryptography.DES.Create",
                                                                                               "System.Security.Cryptography.RC2.Create");

        private static readonly ImmutableArray<string> BadCipherProvider = ImmutableArray.Create("System.Security.Cryptography.DESCryptoServiceProvider",
                                                                                                 "System.Security.Cryptography.RC2CryptoServiceProvider");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Rule);

        protected static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
        {
            var expression = nodeHelper.GetInvocationExpressionNode(ctx.Node);
            if (expression != null)
            {
                var symbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;
                if (symbol != null)
                {
                    foreach (string cipher in BadCipherCreate)
                    {
                        if (!symbol.IsType(cipher))
                            continue;

                        var diagnostic = Diagnostic.Create(Rule, expression.GetLocation(), cipher);
                        ctx.ReportDiagnostic(diagnostic);
                    }
                }
            }

            if (nodeHelper.IsObjectCreationExpressionNode(ctx.Node))
            {
                var symbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;
                if (symbol != null)
                {
                    foreach (string cipher in BadCipherProvider)
                    {
                        if (!symbol.ContainingSymbol.IsType(cipher))
                            continue;

                        var diagnostic = Diagnostic.Create(Rule, ctx.Node.GetLocation(), cipher);
                        ctx.ReportDiagnostic(diagnostic);
                    }
                }
            }
        }
    }
}
