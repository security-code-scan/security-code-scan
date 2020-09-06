#nullable disable
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
    public class RequestValidationAnalyzerCSharp : RequestValidationAnalyzer
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
            base.Initialize(context);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(ctx => CheckAllowHtml(ctx, CSharpSyntaxNodeHelper.Default),     CSharp.SyntaxKind.PropertyDeclaration);
            context.RegisterSyntaxNodeAction(ctx => CheckUnvalidated(ctx, CSharpSyntaxNodeHelper.Default),   CSharp.SyntaxKind.SimpleMemberAccessExpression);
            context.RegisterSyntaxNodeAction(ctx => CheckValidateInput(ctx, CSharpSyntaxNodeHelper.Default), CSharp.SyntaxKind.MethodDeclaration);
            context.RegisterSyntaxNodeAction(ctx => CheckValidateInput(ctx, CSharpSyntaxNodeHelper.Default), CSharp.SyntaxKind.ClassDeclaration);
        }
    }

    [DiagnosticAnalyzer(LanguageNames.VisualBasic)]
    public class RequestValidationAnalyzerVisualBasic : RequestValidationAnalyzer
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
            base.Initialize(context);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(ctx => CheckAllowHtml(ctx, VBSyntaxNodeHelper.Default),         VB.SyntaxKind.PropertyBlock);
            context.RegisterSyntaxNodeAction(ctx => CheckUnvalidated(ctx, VBSyntaxNodeHelper.Default),       VB.SyntaxKind.SimpleMemberAccessExpression);
            context.RegisterSyntaxNodeAction(ctx => CheckValidateInput(ctx, VBSyntaxNodeHelper.Default),     VB.SyntaxKind.FunctionBlock);
            context.RegisterSyntaxNodeAction(ctx => CheckValidateInput(ctx, VBSyntaxNodeHelper.Default),     VB.SyntaxKind.SubBlock);
            context.RegisterSyntaxNodeAction(ctx => CheckValidateInput(ctx, VBSyntaxNodeHelper.Default),     VB.SyntaxKind.ClassBlock);
        }
    }

    public abstract class RequestValidationAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor                 Rule = LocaleUtil.GetDescriptor("SCS0017");
        private static readonly DiagnosticDescriptor                 InheritanceRule = LocaleUtil.GetDescriptor("SCS0017", "title_base");
        public override         ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Rule, InheritanceRule);

        public override void Initialize(AnalysisContext context)
        {
            if (!Debugger.IsAttached) // prefer single thread for debugging in development
                context.EnableConcurrentExecution();

            if (context.IsAuditMode())
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            else
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            context.RegisterSymbolAction(CheckValidateInputInheritance, SymbolKind.NamedType);
        }

        protected void CheckAllowHtml(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
        {
            var attributes = nodeHelper.GetDeclarationAttributeNodes(ctx.Node);

            foreach (var attribute in attributes)
            {
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

        protected void CheckUnvalidated(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
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

        protected void CheckValidateInput(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
        {
            foreach (var attribute in nodeHelper.GetDeclarationAttributeNodes(ctx.Node))
            {
                var hasArgumentFalse = false;
                SyntaxNode expression = null;
                foreach (var arg in nodeHelper.GetAttributeArgumentNodes(attribute))
                {
                    expression = nodeHelper.GetAttributeArgumentExpressionNode(arg);
                    var expressionValue = ctx.SemanticModel.GetConstantValue(expression);
                    if (!expressionValue.HasValue)
                        continue;

                    if (expressionValue.Value is bool value && value == false)
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

        protected void CheckValidateInputInheritance(SymbolAnalysisContext ctx)
        {
            var classSymbol = (ITypeSymbol)ctx.Symbol;
            if (!classSymbol.IsDerivedFrom("System.Web.Mvc.ControllerBase"))
                return;

            var hasMethodsWithoutAttr = false;
            foreach (var member in classSymbol.GetMembers())
            {
                if (!(member is IMethodSymbol method))
                    continue;

                if(method.MethodKind != MethodKind.Ordinary)
                    continue;

                //this case is handled by CheckValidateInput analyze
                if (method.HasAttribute(attr => attr.AttributeClass.ToString().Equals("System.Web.Mvc.ValidateInputAttribute")))
                    continue;

                var inheritsValidateInput = false;
                for (var baseMethod = method.OverriddenMethod; baseMethod != null; baseMethod = baseMethod.OverriddenMethod)
                {
                    var value = GetValidateInputAttributeParameterValue(baseMethod);
                    if (value == null)
                        continue;

                    inheritsValidateInput = true;

                    if (value == true)
                        break;

                    ctx.ReportDiagnostic(Diagnostic.Create(InheritanceRule, method.Locations[0]));
                    break;
                }

                if (!inheritsValidateInput)
                    hasMethodsWithoutAttr = true;
            }

            if (!hasMethodsWithoutAttr)
                return;

            //this case is handled by CheckValidateInput analyze
            if (classSymbol.HasAttribute(attr => attr.AttributeClass.ToString().Equals("System.Web.Mvc.ValidateInputAttribute")))
                return;

            for (var baseType = classSymbol.BaseType; baseType != null; baseType = baseType.BaseType)
            {
                var value = GetValidateInputAttributeParameterValue(baseType);
                if (value == null)
                    continue;

                if (value == true)
                    return;

                ctx.ReportDiagnostic(Diagnostic.Create(InheritanceRule, ctx.Symbol.Locations[0]));
                return;
            }
        }

        private bool? GetValidateInputAttributeParameterValue(ISymbol symbol)
        {
            var validateInputAttr =
                symbol.GetAttribute(attr => attr.AttributeClass.ToString().Equals("System.Web.Mvc.ValidateInputAttribute"));

            if (validateInputAttr == null)
                return null;

            var constructorArgs = validateInputAttr.ConstructorArguments;
            if (constructorArgs.Length == 0)
                return null;

            return (bool)validateInputAttr.ConstructorArguments[0].Value;
        }
    }
}
