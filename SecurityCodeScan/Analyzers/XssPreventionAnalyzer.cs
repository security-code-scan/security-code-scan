using System;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

namespace SecurityCodeScan.Analyzers
{
    internal class XssPreventionAnalyzerCSharp : TaintAnalyzerExtensionCSharp
    {
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => XssPreventionAnalyzer.SupportedDiagnostics;

        public override void VisitBegin(SyntaxNode node, ExecutionState state, Configuration projectConfiguration)
        {
            if (!(node is CSharpSyntax.MethodDeclarationSyntax method))
                return;

            if (!method.Modifiers.Any(x => x.IsKind(CSharp.SyntaxKind.PublicKeyword)))
                return;

            if (!method.ParameterList.Parameters.Any())
                return;

            if (state.AnalysisContext.SemanticModel.GetSymbolInfo(method.ReturnType).Symbol != state.StringType)
                return;

            if (!(node.Parent is CSharpSyntax.ClassDeclarationSyntax classNode))
                return;

            var classSymbol = CSharp.CSharpExtensions.GetDeclaredSymbol(state.AnalysisContext.SemanticModel, classNode);
            if (classSymbol == null ||
                !classSymbol.IsDerivedFrom(XssPreventionAnalyzer.ControllerNames))
            {
                return;
            }

            if (!XssPreventionAnalyzer.ExecutionStates.TryAdd(state, state))
                throw new Exception("Something went wrong. Failed to add execution state.");
        }

        public override void VisitEnd(SyntaxNode node, ExecutionState state, Configuration projectConfiguration)
        {
            XssPreventionAnalyzer.ExecutionStates.TryRemove(state, out var _);
        }

        public override void VisitStatement(CSharpSyntax.StatementSyntax node,
                                           ExecutionState state,
                                           VariableState statementState,
                                           Configuration projectConfiguration)
        {
            if (!XssPreventionAnalyzer.ExecutionStates.ContainsKey(state))
                return;

            if (!node.IsKind(CSharp.SyntaxKind.ReturnStatement))
                return;

            if ((statementState.Taint & VariableTaint.Tainted) != 0 &&
                (((ulong)statementState.Taint) & projectConfiguration.TaintTypeNameToBit["HtmlEscaped"]) == 0)
            {
                state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(XssPreventionAnalyzer.Rule, node.GetLocation()));
            }
        }

        public override void VisitArrowExpressionClause(CSharpSyntax.ArrowExpressionClauseSyntax node, ExecutionState state, VariableState statementState, Configuration projectConfiguration)
        {
            if (!XssPreventionAnalyzer.ExecutionStates.ContainsKey(state))
                return;

            if ((statementState.Taint & VariableTaint.Tainted) != 0 &&
                (((ulong)statementState.Taint) & projectConfiguration.TaintTypeNameToBit["HtmlEscaped"]) == 0)
            {
                state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(XssPreventionAnalyzer.Rule, node.GetLocation()));
            }
        }
    }

    internal class XssPreventionAnalyzerVisualBasic : TaintAnalyzerExtensionVisualBasic
    {
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => XssPreventionAnalyzer.SupportedDiagnostics;

        public override void VisitBegin(SyntaxNode node, ExecutionState state, Configuration projectConfiguration)
        {
            if (!(node is VBSyntax.MethodBlockSyntax method))
                return;

            if (!method.SubOrFunctionStatement.Modifiers.Any(x => x.IsKind(VB.SyntaxKind.PublicKeyword)))
                return;

            if (!method.SubOrFunctionStatement.ParameterList.Parameters.Any())
                return;

            var retType = method.SubOrFunctionStatement.AsClause?.Type;
            if (retType == null)
                return;

            if (state.AnalysisContext.SemanticModel.GetSymbolInfo(retType).Symbol != state.StringType)
                return;

            if (!(node.Parent is VBSyntax.ClassBlockSyntax classNode))
                return;

            var classSymbol = VB.VisualBasicExtensions.GetDeclaredSymbol(state.AnalysisContext.SemanticModel, classNode);
            if (classSymbol == null ||
                !classSymbol.IsDerivedFrom(XssPreventionAnalyzer.ControllerNames))
            {
                return;
            }

            if (!XssPreventionAnalyzer.ExecutionStates.TryAdd(state, state))
                throw new Exception("Something went wrong. Failed to add execution state.");
        }

        public override void VisitEnd(SyntaxNode node, ExecutionState state, Configuration projectConfiguration)
        {
            XssPreventionAnalyzer.ExecutionStates.TryRemove(state, out var _);
        }

        public override void VisitStatement(VBSyntax.StatementSyntax node,
                                           ExecutionState state,
                                           VariableState statementState,
                                           Configuration projectConfiguration)
        {
            if (!XssPreventionAnalyzer.ExecutionStates.ContainsKey(state))
                return;

            if (!node.IsKind(VB.SyntaxKind.ReturnStatement))
                return;

            if ((statementState.Taint & VariableTaint.Tainted) != 0 &&
                (((ulong)statementState.Taint) & projectConfiguration.TaintTypeNameToBit["HtmlEscaped"]) == 0)
            {
                state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(XssPreventionAnalyzer.Rule, node.GetLocation()));
            }
        }
    }

    internal static class XssPreventionAnalyzer
    {
        public const              string            DiagnosticId = "SCS0029";
        public static readonly DiagnosticDescriptor Rule         = LocaleUtil.GetDescriptor(DiagnosticId);

        public static ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Rule);

        public static ConcurrentDictionary<ExecutionState, ExecutionState> ExecutionStates = new ConcurrentDictionary<ExecutionState, ExecutionState>();

        public static readonly string[] ControllerNames = { "Microsoft.AspNetCore.Mvc.ControllerBase", "System.Web.Mvc.Controller" };
    }
}
