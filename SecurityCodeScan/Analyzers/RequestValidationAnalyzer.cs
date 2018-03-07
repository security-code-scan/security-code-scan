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
    public class RequestValidationAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor                 Rule = LocaleUtil.GetDescriptor("SCS0017");
        public override         ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            // Separated the parsers on this one as they use too many language dependent syntax types. 
            // TODO: Review to see if this can be simplified.
            context.RegisterSyntaxNodeAction(ctx => CheckAllowHtml(ctx, CSharpSyntaxNodeHelper.Default),     CSharp.SyntaxKind.PropertyDeclaration);
            context.RegisterSyntaxNodeAction(ctx => CheckAllowHtml(ctx, VBSyntaxNodeHelper.Default),         VB.SyntaxKind.PropertyBlock);
            context.RegisterSyntaxNodeAction(ctx => CheckUnvalidated(ctx, CSharpSyntaxNodeHelper.Default),   CSharp.SyntaxKind.SimpleMemberAccessExpression);
            context.RegisterSyntaxNodeAction(ctx => CheckUnvalidated(ctx, VBSyntaxNodeHelper.Default),       VB.SyntaxKind.SimpleMemberAccessExpression);
            context.RegisterSyntaxNodeAction(ctx => CheckValidateInput(ctx, CSharpSyntaxNodeHelper.Default), CSharp.SyntaxKind.MethodDeclaration);
            context.RegisterSyntaxNodeAction(ctx => CheckValidateInput(ctx, VBSyntaxNodeHelper.Default),     VB.SyntaxKind.FunctionBlock);
            context.RegisterSyntaxNodeAction(ctx => CheckValidateInput(ctx, VBSyntaxNodeHelper.Default),     VB.SyntaxKind.SubBlock);
            context.RegisterSyntaxNodeAction(ctx => CheckValidateInput(ctx, CSharpSyntaxNodeHelper.Default), CSharp.SyntaxKind.ClassDeclaration);
            context.RegisterSyntaxNodeAction(ctx => CheckValidateInput(ctx, VBSyntaxNodeHelper.Default),     VB.SyntaxKind.ClassBlock);
        }

        private void CheckAllowHtml(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
        {
            var attributes = nodeHelper.GetDeclarationAttributeNodes(ctx.Node);

            foreach (var attribute in attributes)
            {
                if (!nodeHelper.GetAttributeNameNode(attribute).ToString().Contains("AllowHtml"))
                    continue;

                var attributeSymbols = ctx.SemanticModel.GetSymbolInfo(attribute).Symbol;
                if (attributeSymbols == null)
                    continue;

                var containingSymbol = attributeSymbols.ContainingSymbol.ToString();
                if (containingSymbol == "System.Web.Mvc.AllowHtmlAttribute")
                {
                    ctx.ReportDiagnostic(Diagnostic.Create(Rule, attribute.GetLocation()));
                    break;
                }
            }
        }

        private void CheckUnvalidated(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
        {
            var name = nodeHelper.GetMemberAccessNameNode(ctx.Node);
            if (name.ToString() != "Unvalidated")
                return;

            var memberAccessSymbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;
            if (memberAccessSymbol == null)
                return;

            var containingSymbol = memberAccessSymbol.ContainingSymbol.ToString();
            if (containingSymbol == "System.Web.Helpers.Validation" || containingSymbol == "System.Web.HttpRequestBase")
                ctx.ReportDiagnostic(Diagnostic.Create(Rule, name.GetLocation()));
        }

        private void CheckValidateInput(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
        {
            foreach (var attribute in nodeHelper.GetDeclarationAttributeNodes(ctx.Node))
            {
                if (!nodeHelper.GetAttributeNameNode(attribute).ToString().Contains("ValidateInput"))
                    continue;

                bool hasArgumentFalse = false;
                SyntaxNode expression = null;
                foreach (var arg in nodeHelper.GetAttributeArgumentNodes(attribute))
                {
                    expression = nodeHelper.GetAttributeArgumentExpresionNode(arg);
                    var expressionValue = expression.ToString();
                    if (expressionValue == "false" || expressionValue == "False")
                    {
                        hasArgumentFalse = true;
                        break;
                    }
                }

                if (!hasArgumentFalse || expression == null)
                    continue;

                var attributeSymbols = ctx.SemanticModel.GetSymbolInfo(attribute).Symbol;
                if (attributeSymbols == null)
                    continue;

                var containingSymbol = attributeSymbols.ContainingSymbol.ToString();
                if (containingSymbol == "System.Web.Mvc.ValidateInputAttribute")
                {
                    ctx.ReportDiagnostic(Diagnostic.Create(Rule, expression.GetLocation()));
                    break;
                }
            }
        }

    }
}
