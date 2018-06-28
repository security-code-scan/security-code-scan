using System.Collections.Generic;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.VisualBasic;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using SyntaxKind = Microsoft.CodeAnalysis.CSharp.SyntaxKind;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class UnknownPasswordApiAnalyzerCSharp : TaintAnalyzerExtensionCSharp
    {
        public UnknownPasswordApiAnalyzerCSharp()
        {
            TaintAnalyzerCSharp.RegisterExtension(this);
        }

        private readonly UnknownPasswordApiAnalyzer Analyzer  = new UnknownPasswordApiAnalyzer();

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => Analyzer.SupportedDiagnostics;

        public override void Initialize(AnalysisContext context) { }

        public override void VisitAssignment(CSharpSyntax.AssignmentExpressionSyntax node,
                                             ExecutionState                          state,
                                             MethodBehavior                          behavior,
                                             ISymbol                                 symbol,
                                             VariableState                           variableRightState)
        {
            if (behavior                                                                     != null                               || //Unknown API
                symbol                                                                       == null                               ||
                variableRightState.Taint                                                     != VariableTaint.Constant             ||
                Microsoft.CodeAnalysis.CSharp.CSharpExtensions.Kind(variableRightState.Node) != SyntaxKind.StringLiteralExpression ||
                !Analyzer.IsPasswordField(symbol, state.AnalysisContext.Options.AdditionalFiles))
            {
                return;
            }

            var constValue = state.AnalysisContext.SemanticModel.GetConstantValue(variableRightState.Node);
            if (constValue.HasValue && constValue.Value.Equals(""))
                return;

            var varSymbol = state.GetSymbol(variableRightState.Node);
            if (varSymbol != null && varSymbol.IsType("System.String.Empty"))
                return;

            var diagnostic = Diagnostic.Create(UnknownPasswordApiAnalyzer.Rule, node.GetLocation());
            state.AnalysisContext.ReportDiagnostic(diagnostic);
        }
    }

    [DiagnosticAnalyzer(LanguageNames.VisualBasic)]
    public class UnknownPasswordApiAnalyzerVisualBasic : TaintAnalyzerExtensionVisualBasic
    {
        public UnknownPasswordApiAnalyzerVisualBasic()
        {
            TaintAnalyzerVisualBasic.RegisterExtension(this);
        }

        private readonly UnknownPasswordApiAnalyzer Analyzer = new UnknownPasswordApiAnalyzer();

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => Analyzer.SupportedDiagnostics;

        public override void Initialize(AnalysisContext context) { }

        public override void VisitAssignment(VisualBasicSyntaxNode node,
                                             ExecutionState        state,
                                             MethodBehavior        behavior,
                                             ISymbol               symbol,
                                             VariableState         variableRightState)
        {
            if (behavior                 != null                   || //Unknown API
                symbol                   == null                   ||
                variableRightState.Taint != VariableTaint.Constant ||
                Microsoft.CodeAnalysis.VisualBasic.VisualBasicExtensions.Kind(variableRightState.Node) !=
                Microsoft.CodeAnalysis.VisualBasic.SyntaxKind.StringLiteralExpression ||
                !Analyzer.IsPasswordField(symbol, state.AnalysisContext.Options.AdditionalFiles))
            {
                return;
            }

            var constValue = state.AnalysisContext.SemanticModel.GetConstantValue(variableRightState.Node);
            if (constValue.HasValue && constValue.Value.Equals(""))
                return;

            var varSymbol = state.GetSymbol(variableRightState.Node);
            if (varSymbol != null && varSymbol.IsType("System.String.Empty"))
                return;

            var diagnostic = Diagnostic.Create(UnknownPasswordApiAnalyzer.Rule, node.GetLocation());
            state.AnalysisContext.ReportDiagnostic(diagnostic);
        }
    }

    public class UnknownPasswordApiAnalyzer
    {
        public static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0015", "title_assignment");
        public ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public bool IsPasswordField(ISymbol symbol, ImmutableArray<AdditionalText> additionalTexts)
        {
            var passwordFields = ConfigurationManager.Instance.GetProjectConfiguration(additionalTexts).PasswordFields;
            return passwordFields.Contains(symbol.MetadataName.ToLower());
        }
    }
}
