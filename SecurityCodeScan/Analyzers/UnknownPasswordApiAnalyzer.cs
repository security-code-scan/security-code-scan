using System.Collections.Immutable;
using System.Globalization;
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
    internal class UnknownPasswordApiAnalyzerCSharp : UnknownPasswordApiAnalyzer
    {
        public override void Initialize(ISecurityAnalysisContext context)
        {
            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context, Configuration config)
        {
            OnCompilationStartAction(config);
            context.RegisterSyntaxNodeAction(ctx => VisitAssignment(ctx, CSharpSyntaxNodeHelper.Default), CSharp.SyntaxKind.VariableDeclarator);
            context.RegisterSyntaxNodeAction(ctx => VisitAssignment(ctx, CSharpSyntaxNodeHelper.Default), CSharp.SyntaxKind.SimpleAssignmentExpression);
        }
    }

    [SecurityAnalyzer(LanguageNames.VisualBasic)]
    internal class UnknownPasswordApiAnalyzerVisualBasic : UnknownPasswordApiAnalyzer
    {
        public override void Initialize(ISecurityAnalysisContext context)
        {
            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context, Configuration config)
        {
            OnCompilationStartAction(config);
            context.RegisterSyntaxNodeAction(ctx => VisitAssignment(ctx, VBSyntaxNodeHelper.Default), VB.SyntaxKind.VariableDeclarator);
            context.RegisterSyntaxNodeAction(ctx => VisitAssignment(ctx, VBSyntaxNodeHelper.Default), VB.SyntaxKind.SimpleAssignmentStatement);
            context.RegisterSyntaxNodeAction(ctx => VisitAssignment(ctx, VBSyntaxNodeHelper.Default), VB.SyntaxKind.NamedFieldInitializer);
        }
    }

    internal abstract class UnknownPasswordApiAnalyzer : SecurityAnalyzer
    {
        public static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0015", "title_assignment");
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Rule);

        private Configuration Config;

        protected void OnCompilationStartAction(Configuration config)
        {
            Config = config;
        }

        private bool IsPasswordField(string name, ImmutableArray<AdditionalText> additionalTexts)
        {
            var passwordFields = Config.PasswordFields;
            foreach (var passwordField in passwordFields)
            {
                if (CultureInfo.InvariantCulture.CompareInfo.IndexOf(name, passwordField, CompareOptions.IgnoreCase) >= 0)
                    return true;
            }

            return false;
        }

        protected void VisitAssignment(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
        {
            // todo: if PasswordField is reintroduced to Behaviors need to filter warnings covered by taint analyzer
            var leftNode = nodeHelper.GetAssignmentLeftNodeName(ctx.Node);
            if (!IsPasswordField(leftNode, ctx.Options.AdditionalFiles))
                return;

            var rightNode = nodeHelper.GetAssignmentRightNode(ctx.Node);
            if (rightNode == null)
                return;

            var constValue = ctx.SemanticModel.GetConstantValue(rightNode);
            if (!constValue.HasValue)
                return;

            if (!(constValue.Value is string value))
                return;

            if (value.Equals(string.Empty))
                return;

            var diagnostic = Diagnostic.Create(Rule, ctx.Node.GetLocation());
            ctx.ReportDiagnostic(diagnostic);
        }
    }
}
