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
    public class WeakRandomAnalyzerCSharp : WeakRandomAnalyzer
    {
        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(ctx => VisitSyntaxNode(ctx, CSharpSyntaxNodeHelper.Default), CSharp.SyntaxKind.InvocationExpression);
        }
    }

    [DiagnosticAnalyzer(LanguageNames.VisualBasic)]
    public class WeakRandomAnalyzerVisualBasic : WeakRandomAnalyzer
    {
        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(ctx => VisitSyntaxNode(ctx, VBSyntaxNodeHelper.Default), VB.SyntaxKind.InvocationExpression);
        }
    }

    public abstract class WeakRandomAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0005");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        protected static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
        {
            SyntaxNode expression = nodeHelper.GetInvocationExpressionNode(ctx.Node);

            if (expression == null)
                return;

            var symbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;

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
