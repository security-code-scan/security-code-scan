using System.Collections.Generic;

using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis;

namespace RoslynSecurityGuard.Analyzers.Taint
{
    /// <summary>
    /// Execution state at a given statement. It will be alter after each statement are evaluated.
    /// </summary>
    public class ExecutionState
    {
        public SyntaxNodeAnalysisContext analysisContext { get; }
        private Dictionary<string, VariableState> variables = new Dictionary<string, VariableState>();

        public ExecutionState(SyntaxNodeAnalysisContext ctx)
        {
            this.analysisContext = ctx;
        }

        public void AddNewValue(string identifier, VariableState value) {
            variables.Add(identifier, value);
        }

        public VariableState GetValueByIdentifier(string identifier) {
            VariableState value = new VariableState(VariableTaint.UNKNOWN);
            variables.TryGetValue(identifier, out value);
            return value;
        }

        /// <summary>
        /// Resolve semantic class name of a given variable reference.
        /// </summary>
        /// <param name="node">Expression to evaluate</param>
        /// <returns>The resolved symbol with the complete class name and method name.</returns>
        public ISymbol GetSymbol(ExpressionSyntax node) {
            return analysisContext.SemanticModel.GetSymbolInfo(node).Symbol;
        }

    }
}
