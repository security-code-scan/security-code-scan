using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using VB = Microsoft.CodeAnalysis.VisualBasic;

namespace SecurityCodeScan.Analyzers
{
    [SecurityAnalyzer(LanguageNames.CSharp)]
    internal class WeakRandomAnalyzerCSharp : WeakRandomAnalyzer
    {
        public override void Initialize(ISecurityAnalysisContext context)
        {
            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context, Configuration config)
        {
            context.RegisterSyntaxNodeAction(ctx => VisitSyntaxNode(ctx, CSharpSyntaxNodeHelper.Default), CSharp.SyntaxKind.InvocationExpression);
        }
    }

    [SecurityAnalyzer(LanguageNames.VisualBasic)]
    internal class WeakRandomAnalyzerVisualBasic : WeakRandomAnalyzer
    {
        public override void Initialize(ISecurityAnalysisContext context)
        {
            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context, Configuration config)
        {
            context.RegisterSyntaxNodeAction(ctx => VisitSyntaxNode(ctx, VBSyntaxNodeHelper.Default), VB.SyntaxKind.InvocationExpression);
        }
    }

    internal abstract class WeakRandomAnalyzer : SecurityAnalyzer
    {
        private static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0005");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Rule);

        protected static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
        {
            SyntaxNode expression = nodeHelper.GetInvocationExpressionNode(ctx.Node);

            if (expression == null)
                return;

            var symbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;
            if (symbol == null)
                return;

            //System.Random.Next()
            if (symbol.IsType("System.Random.Next")      ||
                symbol.IsType("System.Random.NextBytes") ||
                symbol.IsType("System.Random.NextDouble"))
            {
                var diagnostic = Diagnostic.Create(Rule, expression.GetLocation());
                ctx.ReportDiagnostic(diagnostic);
            }
        }
    }
}
