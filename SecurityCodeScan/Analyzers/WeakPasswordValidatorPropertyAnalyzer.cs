using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class WeakPasswordValidatorPropertyAnalyzerCSharp : TaintAnalyzerExtensionCSharp
    {
        private readonly WeakPasswordValidatorPropertyAnalyzer Analyzer = new WeakPasswordValidatorPropertyAnalyzer();

        public WeakPasswordValidatorPropertyAnalyzerCSharp()
        {
            TaintAnalyzerCSharp.RegisterExtension(this);
        }

        public override void Initialize(AnalysisContext context)
        {
        }

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => Analyzer.SupportedDiagnostics;

        public override void VisitEnd(SyntaxNode node, ExecutionState state)
        {
            Analyzer.CheckState(state);
        }

        public override void VisitAssignment(CSharpSyntax.AssignmentExpressionSyntax node,
                                             ExecutionState                          state,
                                             MethodBehavior                          behavior,
                                             ISymbol                                 symbol,
                                             VariableState                           variableRightState)
        {
            if (node != null)
                Analyzer.TagVariables(symbol, variableRightState);
        }
    }

    [DiagnosticAnalyzer(LanguageNames.VisualBasic)]
    public class WeakPasswordValidatorPropertyAnalyzerVisualBasic : TaintAnalyzerExtensionVisualBasic
    {
        private readonly WeakPasswordValidatorPropertyAnalyzer Analyzer = new WeakPasswordValidatorPropertyAnalyzer();

        public WeakPasswordValidatorPropertyAnalyzerVisualBasic()
        {
            TaintAnalyzerVisualBasic.RegisterExtension(this);
        }

        public override void Initialize(AnalysisContext context)
        {
        }

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => Analyzer.SupportedDiagnostics;

        public override void VisitEnd(SyntaxNode node, ExecutionState state)
        {
            Analyzer.CheckState(state);
        }

        public override void VisitAssignment(VB.VisualBasicSyntaxNode node,
                                             ExecutionState           state,
                                             MethodBehavior           behavior,
                                             ISymbol                  symbol,
                                             VariableState            variableRightState)
        {
            if (node is VBSyntax.AssignmentStatementSyntax || node is VBSyntax.NamedFieldInitializerSyntax)
                Analyzer.TagVariables(symbol, variableRightState);
        }
    }

    internal class WeakPasswordValidatorPropertyAnalyzer
    {
        private static readonly DiagnosticDescriptor RulePasswordLength                  = LocaleUtil.GetDescriptor("SCS0032"); // RequiredLength's value is too small
        private static readonly DiagnosticDescriptor RulePasswordValidators              = LocaleUtil.GetDescriptor("SCS0033"); // Not enough properties set
        private static readonly DiagnosticDescriptor RuleRequiredPasswordValidators      = LocaleUtil.GetDescriptor("SCS0034"); // Required property must be set

        public ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(RulePasswordLength,
                                                                                                  RulePasswordValidators,
                                                                                                  RuleRequiredPasswordValidators);

        public  void CheckState(ExecutionState state)
        {
            // For every variables registered in state
            foreach (var variableState in state.VariableStates)
            {
                var st = variableState.Value;

                var symbol = state.GetSymbol(st.Node);
                if(symbol == null)
                    continue;

                // Only if it is the constructor of the PasswordValidator instance
                if (!symbol.IsConstructor() || !symbol.ContainingSymbol.ToString().Equals("Microsoft.AspNet.Identity.PasswordValidator"))
                    continue;

                var configuration = ConfigurationManager
                                           .Instance.GetProjectConfiguration(state.AnalysisContext.Options.AdditionalFiles);

                var minimumRequiredProperties = configuration.MinimumPasswordValidatorProperties;
                // If the PasswordValidator instance doesn't have enough properties set
                if (st.Tags.Count < minimumRequiredProperties)
                {
                    state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RulePasswordValidators,
                                                                             variableState.Value.Node.GetLocation(), minimumRequiredProperties));
                }

                if (st.Tags.Contains(Tag.RequiredLengthIsSet))
                {
                    var requiredLength = configuration.PasswordValidatorRequiredLength;
                    var currentValue   = st.GetTags(Tag.RequiredLengthIsSet).First().Value;
                    if (currentValue is int intValue && intValue < requiredLength)
                        state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RulePasswordLength, st.Node.GetLocation(), requiredLength));
                }

                var requiredProperties = configuration.PasswordValidatorRequiredProperties;

                if (!st.Tags.Contains(Tag.RequiredLengthIsSet) && requiredProperties.Contains("RequiredLength"))
                {
                    state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RuleRequiredPasswordValidators,
                                                                                 variableState.Value.Node.GetLocation(), "RequiredLength"));
                }

                if (!st.Tags.Contains(Tag.RequireDigitIsSet) && requiredProperties.Contains("RequireDigit"))
                {
                    state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RuleRequiredPasswordValidators,
                                                                             variableState.Value.Node.GetLocation(), "RequireDigit"));
                }

                if (!st.Tags.Contains(Tag.RequireLowercaseIsSet) && requiredProperties.Contains("RequireLowercase"))
                {
                    state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RuleRequiredPasswordValidators,
                                                                             variableState.Value.Node.GetLocation(), "RequireLowercase"));
                }

                if (!st.Tags.Contains(Tag.RequireNonLetterOrDigitIsSet) && requiredProperties.Contains("RequireNonLetterOrDigit"))
                {
                    state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RuleRequiredPasswordValidators,
                                                                             variableState.Value.Node.GetLocation(), "RequireNonLetterOrDigit"));
                }

                if (!st.Tags.Contains(Tag.RequireUppercaseIsSet) && requiredProperties.Contains("RequireUppercase"))
                {
                    state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RuleRequiredPasswordValidators,
                                                                             variableState.Value.Node.GetLocation(), "RequireUppercase"));
                }
            }
        }

        public void TagVariables(ISymbol symbol, VariableState variableRightState)
        {
            // Only PasswordValidator properties will cause a new tag to be added
            if (symbol.ContainingType.ToString() != "Microsoft.AspNet.Identity.PasswordValidator")
                return;

            var variableValue = variableRightState.Value;
            if (variableRightState.Taint != VariableTaint.Constant)
                variableValue = null;

            if (symbol.Name == "RequiredLength")
            {
                int? requiredLenght = null;
                if (variableValue is int intValue)
                    requiredLenght = intValue;

                variableRightState.RemoveTag(Tag.RequiredLengthIsSet);
                variableRightState.AddTag(Tag.RequiredLengthIsSet, requiredLenght);
            }

            if (!(variableValue is bool boolValue))
                boolValue = true; // TODO: In case of auditing mode, show warning that value unknown

            if (symbol.Name == "RequireDigit")
            {
                if (boolValue)
                    variableRightState.AddTag(Tag.RequireDigitIsSet);
                else
                    variableRightState.RemoveTag(Tag.RequireDigitIsSet);
            }
            else if (symbol.Name == "RequireLowercase")
            {
                if (boolValue)
                    variableRightState.AddTag(Tag.RequireLowercaseIsSet);
                else
                    variableRightState.RemoveTag(Tag.RequireLowercaseIsSet);
            }
            else if (symbol.Name == "RequireNonLetterOrDigit")
            {
                if (boolValue)
                    variableRightState.AddTag(Tag.RequireNonLetterOrDigitIsSet);
                else
                    variableRightState.RemoveTag(Tag.RequireNonLetterOrDigitIsSet);
            }
            else if (symbol.Name == "RequireUppercase")
            {
                if (boolValue)
                    variableRightState.AddTag(Tag.RequireUppercaseIsSet);
                else
                    variableRightState.RemoveTag(Tag.RequireUppercaseIsSet);
            }
        }
    }
}
