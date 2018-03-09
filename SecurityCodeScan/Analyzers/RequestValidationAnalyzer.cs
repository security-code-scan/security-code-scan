using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using VB = Microsoft.CodeAnalysis.VisualBasic;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class RequestValidationAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor                 Rule = LocaleUtil.GetDescriptor("SCS0017");
        private static readonly DiagnosticDescriptor                 InheritanceRule = LocaleUtil.GetDescriptor("SCS0035");
        public override         ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule, InheritanceRule);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(ctx => CheckAllowHtml(ctx, CSharpSyntaxNodeHelper.Default),     CSharp.SyntaxKind.PropertyDeclaration);
            context.RegisterSyntaxNodeAction(ctx => CheckAllowHtml(ctx, VBSyntaxNodeHelper.Default),         VB.SyntaxKind.PropertyBlock);
            context.RegisterSyntaxNodeAction(ctx => CheckUnvalidated(ctx, CSharpSyntaxNodeHelper.Default),   CSharp.SyntaxKind.SimpleMemberAccessExpression);
            context.RegisterSyntaxNodeAction(ctx => CheckUnvalidated(ctx, VBSyntaxNodeHelper.Default),       VB.SyntaxKind.SimpleMemberAccessExpression);
            context.RegisterSyntaxNodeAction(ctx => CheckValidateInput(ctx, CSharpSyntaxNodeHelper.Default), CSharp.SyntaxKind.MethodDeclaration);
            context.RegisterSyntaxNodeAction(ctx => CheckValidateInput(ctx, VBSyntaxNodeHelper.Default),     VB.SyntaxKind.FunctionBlock);
            context.RegisterSyntaxNodeAction(ctx => CheckValidateInput(ctx, VBSyntaxNodeHelper.Default),     VB.SyntaxKind.SubBlock);
            context.RegisterSyntaxNodeAction(ctx => CheckValidateInput(ctx, CSharpSyntaxNodeHelper.Default), CSharp.SyntaxKind.ClassDeclaration);
            context.RegisterSyntaxNodeAction(ctx => CheckValidateInput(ctx, VBSyntaxNodeHelper.Default),     VB.SyntaxKind.ClassBlock);
            context.RegisterSymbolAction(CheckValidateInputInheritance, SymbolKind.NamedType, SymbolKind.Method);
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

                var hasArgumentFalse = false;
                SyntaxNode expression = null;
                foreach (var arg in nodeHelper.GetAttributeArgumentNodes(attribute))
                {
                    expression = nodeHelper.GetAttributeArgumentExpresionNode(arg);
                    var expressionValue = ctx.SemanticModel.GetConstantValue(expression);
                    if (!expressionValue.HasValue)
                        continue;

                    if (expressionValue.Value.ToString() == "false" || expressionValue.Value.ToString() == "False")
                    {
                        hasArgumentFalse = true;
                        break;
                    }
                }

                if (!hasArgumentFalse)
                    continue;

                var attributeSymbols = ctx.SemanticModel.GetSymbolInfo(attribute).Symbol;
                if (attributeSymbols == null)
                    continue;

                var containingSymbol = attributeSymbols.ContainingSymbol.ToString();
                if (containingSymbol != "System.Web.Mvc.ValidateInputAttribute")
                    continue;

                ctx.ReportDiagnostic(Diagnostic.Create(Rule, expression.GetLocation()));
                return;
            }
        }

        private void CheckValidateInputInheritance(SymbolAnalysisContext ctx)
        {
            var classSymbol = (ITypeSymbol)(ctx.Symbol is IMethodSymbol ? ctx.Symbol.ContainingSymbol : ctx.Symbol);
            if (!classSymbol.IsDerivedFrom("System.Web.Mvc.Controller"))
                return;

            if (ctx.Symbol.HasAttribute(attr => attr.AttributeClass.ToString().Equals("System.Web.Mvc.ValidateInputAttribute")))
                return;

            for (var baseType = GetBaseSymbols(ctx.Symbol); baseType != null; baseType = GetBaseSymbols(baseType))
            {
                var validateInputAttr =
                    baseType.GetAttribute(attr => attr.AttributeClass.ToString().Equals("System.Web.Mvc.ValidateInputAttribute"));
                if (validateInputAttr == null)
                    break;

                var argValue = validateInputAttr.ConstructorArguments[0].Value.ToString();
                if (argValue.Equals("true") || argValue.Equals("True"))
                    return;

                ctx.ReportDiagnostic(Diagnostic.Create(InheritanceRule, ctx.Symbol.Locations[0]));
            }
        }

        private ISymbol GetBaseSymbols(ISymbol symbols)
        {
            switch (symbols)
            {
                case ITypeSymbol typeSymbol:
                    return typeSymbol.BaseType;
                case IMethodSymbol methodSymbol:
                    return methodSymbol.OverriddenMethod;
                default:
                    return null;
            }
        }
    }
}
