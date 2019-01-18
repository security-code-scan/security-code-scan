using System.Collections.Generic;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Analyzers
{
    internal class WeakPasswordValidatorPropertyAnalyzerCSharp : TaintAnalyzerExtensionCSharp
    {
        private readonly WeakPasswordValidatorPropertyAnalyzer Analyzer = new WeakPasswordValidatorPropertyAnalyzer();

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => Analyzer.SupportedDiagnostics;

        public override void VisitEnd(SyntaxNode node, ExecutionState state, Configuration configuration)
        {
            Analyzer.CheckState(state, configuration);
        }
    }

    internal class WeakPasswordValidatorPropertyAnalyzerVisualBasic : TaintAnalyzerExtensionVisualBasic
    {
        private readonly WeakPasswordValidatorPropertyAnalyzer Analyzer = new WeakPasswordValidatorPropertyAnalyzer();

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => Analyzer.SupportedDiagnostics;

        public override void VisitEnd(SyntaxNode node, ExecutionState state, Configuration configuration)
        {
            Analyzer.CheckState(state, configuration);
        }
    }

    internal class WeakPasswordValidatorPropertyAnalyzer
    {
        private static readonly DiagnosticDescriptor RulePasswordLength                  = LocaleUtil.GetDescriptor("SCS0032"); // RequiredLength's value is too small
        private static readonly DiagnosticDescriptor RulePasswordValidators              = LocaleUtil.GetDescriptor("SCS0033"); // Not enough properties set
        private static readonly DiagnosticDescriptor RuleRequiredPasswordValidators      = LocaleUtil.GetDescriptor("SCS0034"); // Required property must be set

        private static readonly string[] BoolPropertyNames =  { "RequireDigit", "RequireLowercase", "RequireNonLetterOrDigit", "RequireUppercase" };

        public ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(RulePasswordLength,
                                                                                                  RulePasswordValidators,
                                                                                                  RuleRequiredPasswordValidators);

        public void CheckState(ExecutionState state, Configuration configuration)
        {
            var visited = new HashSet<VariableState>();
            // For every variables registered in state
            foreach (var variableState in state.VariableStates.Values)
            {
                CheckState(variableState, state, visited, configuration);
            }
        }

        private void CheckState(VariableState variableState, ExecutionState state, HashSet<VariableState> visited, Configuration configuration)
        {
            if (!visited.Add(variableState))
                return;

            foreach (var propertyStatesValue in variableState.PropertyStates.Values)
            {
                CheckState(propertyStatesValue, state, visited, configuration);
            }

            var symbol = state.GetSymbol(variableState.Node);
            if(symbol == null)
                return;

            // Only if it is the constructor of the PasswordValidator instance
            if (!symbol.IsConstructor() || !symbol.ContainingSymbol.ToString().Equals("Microsoft.AspNet.Identity.PasswordValidator"))
                return;

            var propertiesCount = 0;
            var requiredProperties = configuration.PasswordValidatorRequiredProperties;

            if (!variableState.PropertyStates.TryGetValue("RequiredLength", out var requiredLenghtState))
            {
                if (requiredProperties.Contains("RequiredLength"))
                    state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RuleRequiredPasswordValidators,
                                                                             variableState.Node.GetLocation(), "RequiredLength"));
            }
            else
            {
                propertiesCount++;
                var requiredLength = configuration.PasswordValidatorRequiredLength;
                if ((requiredLenghtState.Taint == VariableTaint.Constant &&
                     requiredLenghtState.Value is int intValue           && intValue < requiredLength) ||
                    requiredLenghtState.Taint != VariableTaint.Constant && configuration.AuditMode)
                {
                    state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RulePasswordLength, variableState.Node.GetLocation(), requiredLength));
                }
            }

            foreach (var propertyName in BoolPropertyNames)
            {
                if (!variableState.PropertyStates.TryGetValue(propertyName, out var propertyState) ||
                    (propertyState.Taint == VariableTaint.Constant &&
                    propertyState.Value is bool isRequired && !isRequired) ||
                    propertyState.Taint != VariableTaint.Constant && configuration.AuditMode)
                {
                    if (requiredProperties.Contains(propertyName))
                    {
                        state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RuleRequiredPasswordValidators,
                                                                                 variableState.Node.GetLocation(), propertyName));
                    }
                }
                else
                {
                    propertiesCount++;
                }
            }

            var minimumRequiredProperties = configuration.MinimumPasswordValidatorProperties;
            // If the PasswordValidator instance doesn't have enough properties set
            if (propertiesCount < minimumRequiredProperties)
            {
                state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RulePasswordValidators,
                                                                         variableState.Node.GetLocation(), minimumRequiredProperties));
            }
        }
    }
}
